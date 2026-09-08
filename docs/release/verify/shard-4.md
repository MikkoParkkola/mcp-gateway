<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Shard 4 — verification of RELEASE-4.0.0-criteria-status.md lines 285-360

Method per row: read the row's citations, check each at source (`sed -n`, `rg -n`, `git log`/`git show`,
`cargo test`), refute before reporting. Header vocabulary read at lines 1-60 first. `enable_idempotency`
(line 288) skipped — already verified by the coordinating session today (live caller confirmed,
`7851736d` confirmed ancestor of HEAD).

## Rows checked

| item | row claim | command run | result |
|---|---|---|---|
| `with_tool_registry` (line 289) | `meta_mcp/mod.rs:919`, "tool registry never attached" | `rg -n "pub fn with_tool_registry" src/gateway/meta_mcp/mod.rs` → def at `:948`, carries `#[allow(dead_code)]`; `rg -n "\.with_tool_registry\(" src/ tests/` → zero hits anywhere | **DRIFT** (29 lines, `:919`→`:948`). Claim itself ("never attached") holds: zero callers found in src/ or tests/. |
| `set_error_budget_config` (line 290) | `meta_mcp/mod.rs:972`, wired 2026-09-05 at `server/mod.rs:615` | def actually at `:1001` (`rg -n "pub fn set_error_budget_config"`); `sed -n '615p' src/gateway/server/mod.rs` → exact match, `meta_mcp.set_error_budget_config(backend_budget);` | **DRIFT** on the setter-def line only (29 lines, `:972`→`:1001`). The load-bearing wiring citation (`server/mod.rs:615`) is exact. |
| `set_capability_budget_config` (line 291) | `meta_mcp/mod.rs:977`, wired 2026-09-05 at `server/mod.rs:616` | def actually at `:1006` (29-line drift, same pattern as above); `sed -n '616p' src/gateway/server/mod.rs` → exact match, `meta_mcp.set_capability_budget_config(capability_budget);` | **DRIFT** on setter-def line only; wiring citation exact. |
| `set_playbook_engine` (line 293-294) | `meta_mcp/invoke.rs:2882`, "carries the same attribute" (i.e. `#[allow(dead_code)]`), wired at `server/mod.rs:965` | def actually at `invoke.rs:3058` (176-line drift) — content there confirms `#[allow(dead_code)]` immediately precedes `pub fn set_playbook_engine`; `sed -n '958,972p' server/mod.rs` shows `:965` lands mid-comment ("Load playbooks if enabled") not a call site — actual call site is `:985` (`meta_mcp.set_playbook_engine(engine);`), 20-line drift. `rg -n "\.set_playbook_engine\("` also shows prod call sites `server/mod.rs:985,1593,2921` plus two test call sites. | **DRIFT** on both citations (176 lines and 20 lines respectively). Underlying claim ("IS wired", attribute present) is TRUE at the corrected lines — multiple non-test callers exist. Not a contradiction of content, but citation is stale enough (176 lines) that a reader following it lands on unrelated code (`server_safety`/`circuit_breakers` JSON building). |
| `NFR.COMPAT.1` (line 360) | See full row — matrix of `SUPPORTED_VERSIONS`/`PROTOCOL_VERSION`/`MODERN_VERSIONS`, `server.modern_protocol` default, discovery advertisement, 7 named tests in `tests/nfr_compat1_revisions.rs` | See sub-checks below | **NO CONTRADICTION** — every citation checked confirms the stated content once drift is accounted for (see below). |

### NFR.COMPAT.1 sub-checks

- `PROTOCOL_VERSION` at `src/protocol/mod.rs:27` — exact: `pub const PROTOCOL_VERSION: &str = "2025-11-25";`. Match.
- `SUPPORTED_VERSIONS` at `src/protocol/mod.rs:49` — exact: `&["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]`. Matches the row's claimed list verbatim; modern revision correctly absent.
- `negotiate_version` claimed at `:53` — actual `fn negotiate_version` at `:54`. Trivial 1-line drift (doc-comment line above), not a contradiction.
- `MODERN_VERSIONS` at `src/protocol/meta.rs:248` — exact: `pub const MODERN_VERSIONS: &[&str] = &["2026-07-28"];`. Match.
- `server.modern_protocol` "now defaults to true... `src/config/mod.rs:1236`, landed in `83c98902` on 2026-09-04" — `Default for ServerConfig` sets `modern_protocol: true` (confirmed, though at a slightly different line in current tree — content matches, drift not separately measured since the row already only claims the fact, not a precise anchor for this sub-clause). `git log -1 83c98902` → `fix(config): serve the modern revision by default`, authored `2026-09-04 18:09:47 +0300`. Commit message confirms exactly the mechanism described (deleted field-level `#[serde(default)]`, flipped container default to `true`). Date and mechanism match the row. **Confirmed, not contradicted.**
- Discovery advertisement citation `meta_mcp/mod.rs:1092-1099` — content at that exact range is unrelated (`session_promoted` cleanup + `active_profile` doc comment). The actual code matching the claimed behavior ("Discovery advertises... the legacy negotiation list plus the modern revisions when the switch... is on", iterating `crate::protocol::meta::MODERN_VERSIONS`) is at `meta_mcp/mod.rs:1177-1195` (verified via `rg -n "MODERN_VERSIONS" src/gateway/meta_mcp/mod.rs` → single hit at `:1191`, confirmed by reading `:1175-1200`). **DRIFT, but large (≈90 lines)** — a reader following the cited range lands on unrelated code. No uncommitted changes to this file (`git status --short` clean), so this is drift from prior commits since the row was last re-anchored, not uncommitted local state. Content claim itself is TRUE at the corrected location.
- `tests/nfr_compat1_revisions.rs`, "7 green 2026-09-08": file exists, contains exactly 7 `#[tokio::test]` functions with the exact names cited (`compat_2026_07_28_is_served_on_the_stateless_path`, `compat_2026_07_28_is_refused_when_the_stateless_path_is_off`, `compat_2025_11_25_is_published_by_discovery`, `compat_2025_06_18_is_negotiated_not_downgraded`, `compat_2025_03_26_is_negotiated_not_downgraded`, `compat_2024_11_05_is_negotiated_not_downgraded`, `compat_an_unknown_revision_is_downgraded_to_the_fallback`). Ran `cargo test --test nfr_compat1_revisions --quiet` → `test result: ok. 7 passed; 0 failed`. **Confirmed exactly.** Spot-checked `compat_2026_07_28_is_refused_when_the_stateless_path_is_off` body: asserts `StatusCode::BAD_REQUEST` and `UNSUPPORTED_PROTOCOL_VERSION` error code when `modern_protocol: false` — a real, falsifiable assertion (not vacuous).

### Prose claims in range (not row-anchored, checked as part of context)

- Line 296-303 (budget-setter wiring prose, GH475.CFG.5 reference): `docs/design/2026-09-05-error-budget-test-plan.md` exists (confirmed `test -f`). Prose is consistent with the actual `GH475.CFG.5` row content at line 421 (outside this shard's range — not independently re-verified, only cross-read for consistency; no contradiction found between the two).
- Lines 313-323 (`enable_idempotency` departure note, `with_tool_registry` DoD-2-violation note): consistent with source — `with_tool_registry` genuinely has zero callers and the `#[allow(dead_code)]` attribute is present, matching "no acceptance criterion depends on it" framing. Not independently contradicted.

## Verdict summary

No row in this range asserts something source actively contradicts. Every discrepancy found is
**citation drift** (content exists and is correct, but the cited line number has moved since the
row was last re-anchored) — ranging from trivial (1 line) to large (176 lines, `set_playbook_engine`;
~90 lines, the discovery-advertisement citation in `NFR.COMPAT.1`). None of these files carry
uncommitted changes (`git status --short` clean on all three touched: `meta_mcp/mod.rs`,
`meta_mcp/invoke.rs`, `server/mod.rs`), so the drift is from commits landed after the row was
written, not from another session's in-flight edit — worth re-anchoring but not a correctness defect
in the underlying claims.

No verdict-right-reasoning-wrong row found in this range: every verdict's cited mechanism, once
followed past the drift, actually supports the verdict.
