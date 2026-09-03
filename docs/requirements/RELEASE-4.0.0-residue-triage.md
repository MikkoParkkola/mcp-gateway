<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# The residue, triaged

The blocking rows that no named cluster accounts for, derived from the ledger rather
than transcribed from the rollup, and sorted by what each one is waiting on.

## How the population was derived

`python3 scripts/release/count-release-criteria.py --check`, verbatim:

```
Coverage: 146 criteria, 146 rows, 102 met or non-blocking, 44 blocking.
```

Every row in `docs/requirements/RELEASE-4.0.0-criteria-status.md` whose blocking cell
reads `yes` was enumerated, then the seven clusters named in
`docs/requirements/RELEASE-4.0.0-blocking-rollup.md` were subtracted by membership:

| cluster | rows | count |
|---|---|---|
| A MIK-7212 continuation envelope | `MRTR.1a/1b/3a/3b/7a/7b/8a/8b/10a`, `NFR.SEC.2/3/4`, `NFR.OBS.4`, `NFR.PERF.3` | 14 |
| B MIK-7217 era detection | `DISCOVER.4a/4b/5a/5b`, `NFR.OBS.3` | 5 |
| C MIK-7272 revision surface | `ORDER.2a/2b`, `SUB.2b`, `SUB.4`, `EXT.1`, `OTEL.1`, `TASK.1` | 7 |
| D MIK-7213 response-cache keying | `CACHE.4a/4b` | 2 |
| E performance measurement | `NFR.PERF.1` | 1 |
| F compatibility and surface facts | `NFR.COMPAT.1`, `NFR.COMPAT.4` | 2 |
| G stdio dispatch path | `NFR.OBS.1`, `NFR.OBS.2`, `MIK-7246.CONFIRM.1a` | 3 |
| **residue** | below | **10** |

34 clustered + 10 residue = 44, the script's blocking total. Ten matches the rollup's
residue count. The rollup's prose list under *The residue, one line each* names nine,
because `MIK-7214.HEADER.9` was split into `9a` and `9b` in the ledger and the prose was
not resplit with it. The ten below are the ledger's.

## The ten

| criterion | what it requires | current state, with file:line | what is actually missing | class |
|---|---|---|---|---|
| `MIK-7214.HEADER.9a` | outbound modern `_meta` and standard headers emitted only where the peer negotiated a modern era | `build_mcp_headers` (`src/transport/http/mod.rs:544-636`) is the single outbound header builder by its own doc comment and inserts `MCP-Protocol-Version` (`:570`) and `MCP-Session-Id` (`:605`, `:608`) on every outbound request, with no branch on the peer's era | a decision on where a per-backend negotiated era is read at header-build time, and what an outbound `_meta` envelope carries. `docs/design/2026-08-31-discover-outbound-era-probe.md:16-23` places this explicitly OUT of the era-probe increment and names HEADER.9 as its owner | DESIGN |
| `MIK-7214.HEADER.9b` | outbound header values derived from the negotiated envelope, not the legacy handshake version | same builder, same lines; the value written is the handshake constant, and `PROTOCOL_VERSION` / `SUPPORTED_VERSIONS` in `src/protocol/mod.rs` carry no 2026 revision, so no negotiated value exists to derive from | the same decision as `9a` — one mechanism, one design | DESIGN |
| `MIK-6704.IDENT.1a` | authorization MUST derive from the authenticated credential | implemented and consumed: `principal_of` (`src/gateway/auth.rs:38-43`) digests the validated secret, set from the bearer token at `:209`, the API key at `:224`, and the OIDC client identity at `src/key_server/mod.rs:154` | an assertion. `tests/auth_tests.rs` uses `principal` only as `String::new()` (`:166`, `:241`, `:255`, `:268`); the three IDENT.1 tests in `tests/mik_6704_acs.rs` (`:30`, `:46`, `:138`) all prove the negative clause, now scored as `1b` | TEST |
| `MIK-6865.SCHEMA.1c` | tool schemas MUST stay within the revision's `$ref` and composition bounds | the only `$ref` handling in the tree is OpenAPI import (`src/capability/openapi/refs.rs:75`), which resolves references inward; `tests/schema_2020_12_validity.rs` contains no `$ref`, `allOf`, `anyOf` or `oneOf` | an assertion over the emitted surface. Inbound resolution is a plausible reason no `$ref` survives outbound, and a plausible reason is not a verdict | TEST |
| `MIK-7215.CONTROL.3a` | transparency log MUST retain a correlation key across the removal of sessions | `src/gateway/meta_mcp/invoke.rs:1812-1816` reads the `_meta` W3C trace id, falls back to `session_id`, then to a literal placeholder. After this release there is no session, so a caller sending no `_meta` trace id is logged under that placeholder | a decision on what supplies the key when the caller sends none. A per-invocation id is already minted at `src/gateway/meta_mcp/invoke.rs:767` (`trace::generate()`) and that chain does not consult it | DESIGN |
| `MIK-7215.CONTROL.4` | session-lifecycle TTL-reaping owns cleanup previously done by disconnect | `SessionLifecycle::{register,track,reap}` (`src/gateway/session_lifecycle.rs:48`, `:107`, `:124`) is implemented and unit-tested (`tests/mik_7215_controls_acs.rs`, `mod lifecycle`); `rg SessionLifecycle` outside the module returns only doc comments in `src/security/firewall/**`. Nothing constructs, holds or drives it | what calls `reap` and on what clock, and what the TTL is. `docs/design/2026-09-01-residue-four-rows.md:73-121` establishes that ownership is not the blocker and names both questions without answering either | DESIGN |
| `MIK-7246.CONFIRM.2` | gate MUST be reachable through the MRTR path, so a modern client can confirm | the confirmation path is `elicitation/create` over an SSE session (`src/gateway/proxy.rs:213-243`); `src/gateway/destructive_confirmation.rs:83-84` states that this revision deletes sessions, so a modern call has none to elicit over | whether an equivalent mechanism satisfies a criterion that names a specific one. `docs/design/2026-09-01-residue-four-rows.md:127-146` shows both readings are consistent with the tree, so no reading of code settles it | DECISION |
| `NFR.SEC.1` | no 3.5.0 control becomes inoperative for a modern caller; each has a refusal test | 14 controls enumerated in `docs/requirements/nfr-sec1-control-inventory.md`; twelve carry a refusal test, eight of them new in `tests/nfr_sec1_controls.rs` (8 passed, 0 failed, 2026-09-01) | one test for row 2, agent JWT validity, which needs an agent registry and a signed token (`nfr-sec1-control-inventory.md:107`). Row 5, the client circuit breaker, refuses on a trip count and has no absent input to remove (`:108`); reclassifying it is the operator's call and it stays counted until made | TEST |
| `NFR.SEC.6` | MIK-7249, MIK-7256, MIK-7262 and MIK-7222 closed in this release | 7222 has `tests/mik_7222_acs.rs`; 7256 is referenced across `src/config/env_overlay.rs` and `src/config_reload/mod.rs`; 7249 is fixed and asserted (`src/config_reload/mod.rs:279`, `:285`, test at `:346`); 7262's fix is the early return at `src/capability/definition/mod.rs:1150` | one test on that early return. Whether an unlabelled fix counts as "closed in this release" for traceability is a separate call, and not a code gap | TEST |
| `NFR.PERF.4` | Meta-MCP surface remains 14-16 tools; `server/discover` does not count against it | `benchmarks/public_claims.json:3-6` records `minimum: 14`, `readme_benchmark: 16`, `with_webhook_status: 17`. The 17th is `gateway_webhook_status`, pushed at `src/gateway/meta_mcp_tool_defs.rs:564-566` behind `webhooks_enabled`. Nothing clamps the count | how the 17th stops counting. The operator ruled on 2026-09-02 that the ceiling stands and the requirement is not widened; the mechanism holding it is unchosen | DESIGN |

## Bottom line

| class | rows |
|---|---|
| DESIGN | 5 — `HEADER.9a`, `HEADER.9b`, `CONTROL.3a`, `CONTROL.4`, `NFR.PERF.4` |
| TEST | 4 — `IDENT.1a`, `SCHEMA.1c`, `NFR.SEC.1`, `NFR.SEC.6` |
| DECISION | 1 — `CONFIRM.2` |
| MEASUREMENT | 0 |
| COVERED | 0 |
| UNKNOWN | 0 |

No row is `MEASUREMENT`. The only measurement the residue touches is `NFR.PERF.4`'s tool
count, and that number exists — `benchmarks/public_claims.json:3-6` records it. What is
missing there is the mechanism that holds it, not the count.

No row is `COVERED`. `docs/design/2026-09-01-residue-four-rows.md` covers four of these
rows analytically and is cited above for each, but it makes no decision for `CONTROL.4`:
it establishes that the decision has no owner and stops, which is why that row is
`DESIGN` and not `COVERED`. Its own scope line says it addresses four of a five-row
residue; the residue is ten, and the six rows it does not reach are listed above.

The three designs this triage calls for are `HEADER.9a`+`9b` (one mechanism, one design),
`CONTROL.3a`+`CONTROL.4` (both blocked on what identifies a caller once sessions are
gone), and `NFR.PERF.4` (unrelated to either).
