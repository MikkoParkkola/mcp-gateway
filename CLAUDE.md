<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **mcp-gateway** (11486 symbols, 27961 relationships, 300 execution flows). Use GitNexus MCP tools to understand code, assess impact, and navigate safely.

> If any GitNexus tool warns the index is stale, run `npx gitnexus analyze` in terminal first.

**Bet Responsibility**: mcp-gateway owns Bet 4 — shared platform primitives for integrations, tool routing, hooks, policy, and gateway-mediated capability reuse.

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying fn, class, or method, run `gitnexus_impact({target: "symbolName", direction: "upstream"})` and report blast radius (direct callers, affected processes, risk level) to user.
- **MUST run `gitnexus_detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows.
- **MUST warn user** if impact analysis returns HIGH or CRITICAL risk before proceeding w/ edits.
- When exploring unfamiliar code, use `gitnexus_query({query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on specific symbol — callers, callees, which execution flows it participates in — use `gitnexus_context({name: "symbolName"})`.

## When Debugging

1. `gitnexus_query({query: "<error or symptom>"})` — find execution flows related to issue
2. `gitnexus_context({name: "<suspect function>"})` — see all callers, callees, and process participation
3. `READ gitnexus://repo/mcp-gateway/process/{processName}` — trace full execution flow step by step
4. For regressions: `gitnexus_detect_changes({scope: "compare", base_ref: "main"})` — see what your branch changed

## When Refactoring

- **Renaming**: MUST use `gitnexus_rename({symbol_name: "old", new_name: "new", dry_run: true})` first. Review preview — graph edits are safe, text_search edits need manual review. Then run w/ `dry_run: false`.
- **Extracting/Splitting**: MUST run `gitnexus_context({name: "target"})` to see all incoming/outgoing refs, then `gitnexus_impact({target: "target", direction: "upstream"})` to find all external callers before moving code.
- After any refactor: run `gitnexus_detect_changes({scope: "all"})` to verify only expected files changed.

## Never Do

- NEVER edit fn, class, or method w/o first running `gitnexus_impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols w/ find-and-replace — use `gitnexus_rename` which understands call graph.
- NEVER commit changes w/o running `gitnexus_detect_changes()` to check affected scope.

## Tools Quick Reference

| Tool | When to use | Command |
|------|-------------|---------|
| `query` | Find code by concept | `gitnexus_query({query: "auth validation"})` |
| `context` | 360-degree view of one symbol | `gitnexus_context({name: "validateUser"})` |
| `impact` | Blast radius before editing | `gitnexus_impact({target: "X", direction: "upstream"})` |
| `detect_changes` | Pre-commit scope check | `gitnexus_detect_changes({scope: "staged"})` |
| `rename` | Safe multi-file rename | `gitnexus_rename({symbol_name: "old", new_name: "new", dry_run: true})` |
| `cypher` | Custom graph queries | `gitnexus_cypher({query: "MATCH ..."})` |

## Impact Risk Levels

| Depth | Meaning | Action |
|-------|---------|--------|
| d=1 | WILL BREAK — direct callers/importers | MUST update these |
| d=2 | LIKELY AFFECTED — indirect deps | Should test |
| d=3 | MAY NEED TESTING — transitive | Test if critical path |

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/mcp-gateway/context` | Codebase overview, check index freshness |
| `gitnexus://repo/mcp-gateway/clusters` | All functional areas |
| `gitnexus://repo/mcp-gateway/processes` | All execution flows |
| `gitnexus://repo/mcp-gateway/process/{name}` | Step-by-step execution trace |

## Self-Check Before Finishing

Before completing any code modification task, verify:
1. `gitnexus_impact` was run for all modified symbols
2. No HIGH/CRITICAL risk warnings were ignored
3. `gitnexus_detect_changes()` confirms changes match expected scope
4. All d=1 (WILL BREAK) dependents were updated

## Keeping the Index Fresh

After committing code changes, GitNexus index becomes stale. Re-run analyze to update it:

```bash
npx gitnexus analyze
```

If index previously included embeddings, preserve them by adding `--embeddings`

```bash
npx gitnexus analyze --embeddings
```

To check whether embeddings exist, inspect `.gitnexus/meta.json` — `stats.embeddings` field shows count (0 means no embeddings). **Running analyze w/o `--embeddings` will delete any previously generated embeddings.**

> Claude Code users: A PostToolUse hook handles this automatically after `git commit` and `git merge`.

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->

# mcp-gateway

Universal MCP Gateway | Rust 1.88+ | Edition 2024 | ~101K LOC | MIT

## Product Vision

mcp-gateway sits btw any AI client and any set of MCP tools. Instead of loading hundreds of tool definitions into every request, AI sees compact **Meta-MCP surface** — 14 tools minimum, 16 in README benchmark, 17 when webhook status is surfaced — and discovers right backend tool on demand. This cuts ~89% of context-token overhead on 100-tool stack, removes "pick which tools to connect" tradeoff, and makes `Unlimited` practical answer to `how many tools`.

 gateway is **tool + capability router**, not general chat-completions / embeddings gateway. When backend asks for `sampling/createMessage`connected client still performs model call. OpenAI-compatible prompt-cache helpers exist only `gateway_invoke` can preserve `prompt_cache_key` behavior for backends that call LLM APIs internally.

**Dual-protocol**: MCP + A2A transport adapter. **OWASP Agentic AI Top 10**: 10/10 covered. **Safety posture**: `#![deny(unsafe_code)]`SHA-256 integrity pinning on every capability, mTLS option, message signing, agent identity.

## Current Status

- **v2.10.0** · Rust 1.88+ · Edition 2024 · ~101K LOC · MIT
- Published on crates.io + Homebrew + Glama + VS Code + Cursor one-click install
- **Meta-MCP surface**: 14-16 tools in production scenarios (README benchmark scenario)
- **Capability backends**: 110+ REST capabilities + MCP backends routed via same surface
- **Security**: unsafe forbidden; dependency-status badge; OWASP Agentic AI 10/10 docs at `docs/OWASP_AGENTIC_AI_COMPLIANCE.md`
- **Benchmarks**: machine-readable claims in `benchmarks/public_claims.json` w/ CI drift check
- **Independent reviews**: Ruach Tov Collective's five-tool comparison + mcp-gateway deep dive (linked in README)

## Plan Forward (near-term, technical)

- **Cross-provider agent-bus** (MIK-2970) — shipped in #145; continue raw-POST body support
- **Capability breadth** — HeyGen connector landed; pattern established for new REST providers
- **MCP 2025-11-25 annotation policy** — see MIK-2985: decide pass-through vs override for downstream annotations; ensure gateway meta-tools (`gateway_execute` `gateway_search_tools` `gateway_list_tools`) always carry full hints
- **Clippy drift** — Rust 1.95 landed (#149); keep lint baseline green
- **Dependabot cadence** — high-volume automated PRs; rebase-and-ship once CI is green

## Decisions Locked (do not re-litigate)

| Decision | Rationale | Do not |
|---|---|---|
| **Meta-MCP surface is compact** (14-16 tools target) | Context-token savings are the entire value proposition | Add meta-tools that could be dynamic-discovery tools |
| **mcp-gateway is NOT a chat / embeddings gateway** | Scope boundary; model calls stay with the connected client | Add OpenAI chat-completion proxying as a first-class feature |
| **`#![deny(unsafe_code)]`** | Gateway sits on the trust path for every tool call | Introduce unsafe to chase performance |
| **SHA-256 integrity pinning on every capability** | Supply-chain safety; capability tampering must be detectable | Load capabilities without hash verification |
| **OWASP Agentic AI Top 10 compliance** | Security posture is a shipped differentiator | Regress a covered control without an ADR |
| **Dual MCP + A2A transport** | Cross-provider agent messaging (#145, MIK-2970) | Treat A2A as an afterthought; avoid compiling it out of default builds |
| **Capability definitions public (mcp-gateway) / private (mcp-gateway-private)** | Public catalog for community; private API credentials / deploy configs | Mix private capabilities into the public catalog |
| **`cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`** gates | Zero-debt discipline in Rust source | Ship code with lints suppressed ad hoc |
| **Mixed per-file licensing: MIT core + PolyForm Noncommercial 1.0.0 EE** | Core gateway stays MIT for adoption; security firewall, agent-identity, data-flow, message-signing, policy, response-inspect/scanner, scope-collision, tool-integrity, cost-accounting, key-server, and transparency-log paths require commercial terms for commercial use (see [LICENSE-EE.md](LICENSE-EE.md), v2.11.0+) | Collapse package metadata back to plain MIT |

## Anti-Patterns (things agents get wrong in this repo)

- **Bloating Meta-MCP surface** — every new meta-tool eats context-savings story. Default to dynamic discovery; add meta-tool only if user-visible workflow demands it.
- **Treating gateway like OpenAI proxy** — it is not. Model calls go to connected client via `sampling/createMessage`. prompt-cache helpers are compatibility shim, not product surface.
- **Skipping SHA-256 integrity pinning on new capability** — capability system depends on hash verification end-to-end.
- **Adding `unsafe` w/o ADR** — `forbid(unsafe_code)` gate is deliberate; any exception needs `docs/architecture/` justification.
- **Duplicating MIK-2985 annotation policy work across mcp-gateway and mcp-gateway-private** — resolve pass-through vs override decision once in ADR and apply to both.
- **Ignoring `benchmarks/public_claims.json` drift** — CI check is there b/c README numerical claims have drifted before.

## Guidance for Agents

- **Before editing core router**: check `gitnexus_impact` (see section below) to understand blast radius.
- **When adding capability**: mirror existing `capabilities/*.yaml` pattern; add SHA-256 hash; update `capabilities/README` if inventory is indexed.
- **When changing Meta-MCP tool surface**: update README, `benchmarks/public_claims.json`and tool-count in all badges in one PR (known drift source).
- **Security-sensitive changes**: re-run OWASP Agentic AI checklist in `docs/OWASP_AGENTIC_AI_COMPLIANCE.md`.
- **Dependabot PRs**: rebase-and-ship once green; do not batch-block them.

## Where to Look

| You want to… | Read |
|---|---|
| Onboard a human user | `README.md` |
| Meta-MCP tool surface | `src/gateway/` |
| Capability definitions | `capabilities/*.yaml` |
| Security / firewall | `src/security/` |
| A2A transport | `src/a2a/` |
| Benchmarks + claims | `docs/BENCHMARKS.md` + `benchmarks/public_claims.json` |
| OWASP compliance | `docs/OWASP_AGENTIC_AI_COMPLIANCE.md` |
| Upgrade migrations | `commands/upgrade/` |

## Build & Test

```bash
cargo build                          # debug build
cargo build --release                # release build
cargo test --quiet                   # all tests
cargo test --quiet -- test_name      # single test
cargo clippy --all-targets -- -D warnings  # lint (must pass clean)
cargo fmt --check                    # format check
cargo fmt                            # auto-format
```

## Architecture

Single-binary gateway: AI client -> compact Meta-MCP surface (13-16 tools) -> dynamic discovery of 500+ backend tools.
~90% token savings by not loading all tool definitions into every request.
OWASP Agentic AI Top 10: 10/10 covered. MCP + A2A dual-protocol.

Key modules: `gateway/` (core router, OAuth, streaming, UI), `provider/` (MCP/composite/capability),
`capability/` (discovery, validation), `transport/` (HTTP, stdio), `security/` (firewall, mTLS, message signing, agent identity, memory scanner),
`cost_accounting/` `scheduler/` `skills/` `tool_profiles/` `config_reload/` `a2a/` (A2A transport adapter),
`commands/upgrade` (post-upgrade migration framework).

## Features (Cargo)

`default` `a2a` `config-export` `cost-governance` `discovery` `firewall` `metrics`
`semantic-search` `spec-preview` `tool-profiles` `webui`

## Quality Gates

- `cargo clippy --all-targets -- -D warnings` must be zero warnings
- `cargo fmt --check` must be clean
- `cargo test --quiet` must pass
- No `unsafe` code (`#![deny(unsafe_code)]`)
- 0 TODO/FIXME in Rust source

