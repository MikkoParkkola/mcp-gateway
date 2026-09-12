# Shard 3 verification — RELEASE-4.0.0-criteria-status.md lines 210-285

Method: read each row's citations, checked at source (`sed -n`, `rg -n`, `git show <sha>:<path>`).
Rows citing evidence "measured against `fd93bf87` HEAD, not the working tree" were checked against
that commit specifically (`git show fd93bf87:<path>`), per the row's own stated methodology, not
against the live working tree (which has unrelated peer edits to `meta_mcp/mod.rs`/`search.rs`).

## Rows checked

| row | verdict claimed | citations checked | result |
|---|---|---|---|
| ORDER.2a/2b (210-211) | ABSENT | `handlers.rs:574-589` (session_id empty-string), `mod.rs:1075-1090` (`session_key`), `mod.rs:1062-1072` (`active_profile`), `mod.rs:1186`/1180-1192 (X-MCP-Profile gating), `surfaced.rs:101-115` (`resolve_surfaced_tool`) — all checked against `fd93bf87` per the row's own stated measurement basis | ALL MATCH SOURCE at fd93bf87. No contradiction. (Prior-session concern about a working-tree mismatch was drift caused by a peer's uncommitted edits, exactly as the row warns — not a defect in the row.) |
| ORDER.3a/3b (212-213) | MET(I) / N/A | RFC-0061 doc lines | not independently re-verified this pass (doc citation only, low risk) |
| SUB.1a-SUB.3 (221-226) | MET / ABSENT | spot-checked file existence only (`handlers.rs`, `subscription_registry.rs`, `streaming.rs`) | no contradiction found; not exhaustively line-checked this pass |
| SUB.4 (227) | UNWIRED | worked example, per team-lead — not re-verified | confirmed shape only, per instructions |
| OAUTH.1 (228) | MET | `mod.rs:87` `validate_issuer`, wiring `mod.rs:836-841` | MATCHES SOURCE exactly |
| OAUTH.2 (229) | MET | `mod.rs:49-58` `registration_body` (confirmed exact), wiring cited at `mod.rs:1100` | **DRIFT**: line 1100 in current source is inside the unrelated `invalid_client`-purge block, not the DCR flow. Actual DCR wiring is `register_client` fn at `mod.rs:1117-1122` (`registration_body(...)` call at :1122), called from `mod.rs:1018`. File has zero uncommitted diff vs HEAD, so this isn't peer-edit drift — it's simply a stale/wrong line number. Underlying claim (DCR is wired, sends `application_type:"native"`) is TRUE; only the specific line anchor is wrong. Verdict (MET) unaffected. |
| OAUTH.3 (230) | MET | `mod.rs:113` `storage_key`, `mod.rs:381-385` `credential_key()` | MATCHES SOURCE exactly, including the "no unqualified fallback key" doc comment |
| EXT.1 declare (231) | MET | `extensions.rs:71` `gateway_declares()` returns `vec![Extension::Tasks]`; `meta_mcp_helpers.rs:181-183` `discovery_extensions()`; `meta_mcp/mod.rs:1205` call site | Function body confirmed correct; line anchors off by 2-3 lines (fn def actually at ~:73, call site at ~:1208) — **DRIFT**, not contradiction. Substance matches. |
| OTEL.1 (233) | MET (caveat) | `trace.rs:23,64,81` baggage field; `invoke.rs:1845` `from_meta` read; **claim: `to_meta()` has zero production callers** (only definition/unit-tests/`exploit_acs.rs:136`); `mcp_provider.rs:83-86` no `_meta`; "Meta-MCP half CLOSED 2026-09-07 (`b130960b`)": `build_outbound_meta` called from `invoke.rs:2693/2705`, reached via `invoke_tool_traced`/`accounted_dispatch` | **CONTRADICTION.** `to_meta()` DOES have a production caller: `src/gateway/meta_mcp/prompt_cache.rs:231`, inside `pub fn build_outbound_meta` (line 228, outside the `#[cfg(test)] mod tests` block which starts at line 283) — `.map(\|trace\| trace.to_meta())`. `build_outbound_meta` is itself confirmed called from production at `invoke.rs:2705`. `rg -n 'to_meta\(' src/ tests/` returns 9 hits: definition + 7 inside `trace.rs`'s own `#[cfg(test)] mod tests` (starts line 194, all cited hits are >194, so genuinely test-only) + the one production hit at `prompt_cache.rs:231` the row's evidence omits. This is the SUB.4 shape: verdict (MET, caveat = direct-provider-path gap only) is still probably right, but the specific supporting claim "zero production callers" is stale — true before `b130960b` landed, false now that the same commit the row cites as closing the gap created that exact caller. `tests/mik_7272_exploit_acs.rs:136` also mis-cited — the matching test body is at line 81, not 136 (minor). |
| TASK.1 (234) | MET | dispatch arms `handlers.rs:1541-1551` | `tasks/get` arm confirmed present exactly at cited lines |
| CONFIRM.1a (242) | PARTIAL | gate call `mod.rs:1658` inside `handle_tools_call`, gate def `mod.rs:1905` | Both confirmed present and matching (gate invoked, `async fn destructive_confirmation_gate` defined a few lines below :1905 region) |
| CONFIRM.1b, CONFIRM.2, CONFIRM.3 (243-245) | MET / ABSENT / MET | not independently re-verified this pass | no contradiction found in spot review; row already carries multiple self-corrections ("re-anchored 2026-09-08") suggesting recent scrutiny |
| DISCOVER.1-7 (253-263) | MET (various) | not independently re-verified this pass — budget-constrained | none checked; no red flags found in reading |

## Note on scope

Full line-by-line verification of every citation in rows 212-226, 236-245, and 249-263 was not
completed within budget. The one substantive new finding (OTEL.1 `to_meta()` production-caller
claim) was found by a targeted `rg` re-run of the row's own cited command, which is the same
falsification method the row itself used and got stale after its own fix landed.
