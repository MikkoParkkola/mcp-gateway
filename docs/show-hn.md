---
title: "Show HN draft: a sovereign coding-agent stack (mcp-gateway + botnaut-client + formal-verified constitutional compliance)"
status: draft
target_post_date: TBD
---

# Show HN post draft

## Title options

1. **(Recommended)** Show HN: A sovereign coding-agent stack — MCP gateway, fine-tuned meta-thinker, constitutionally compliant agent (with Z3/TLA+ proofs)
2. Show HN: I hard-forked Goose into a coding agent with a deny-by-default constitutional gate and a formally verified receipt chain
3. Show HN: botnaut-client — sovereign Goose fork with constitutional compliance, HIGGS 3-bit quant, and a fine-tuned meta-thinker

Reasoning: option 1 names all three moving parts. Option 2 leads on the fork, which is the concrete thing HN can run. Option 3 is punchier but assumes the reader already knows Goose; risky for a cold crowd.

## Body (target 800 to 1200 words)

Hi HN,

I am Mikko. Over the last two weeks I have been building what I now think of as a **sovereign coding-agent stack**: four repos that together try to answer the question "what would a coding agent look like if you owned every layer, not just the IDE plugin?" This post is a status report on what's shipped, what's scaffolded, and what's still design-only. I would like HN to break it.

### The problem, in one paragraph

Every "AI coding agent" product today is a thin orchestration layer on top of someone else's LLM API, someone else's tool-call protocol, and someone else's alignment policy. Cursor, Aider, Continue, Claude Code, Codex — they all agree that `agent + tools + context` is the product. None of them own the stack. If OpenAI rewrites the spec, or Anthropic throttles the API, or the upstream MCP protocol ships a backdoor, your agent is downstream of a vendor decision. Sovereignty in this domain is not a vibe, it's an engineering property: you control the protocol boundary, you control the alignment gate, you control the model, you control the proof artefacts.

What I've shipped is four loosely coupled repos that share one thesis — **the agent is the last link in a verifiable chain** — and each of them is independently useful.

### Repo 1 — `mcp-gateway` (the protocol boundary)

The MCP ecosystem treats "connect N servers" as a feature. It's also the entire attack surface: Invariant Labs demonstrated tool-poisoning, rug-pulls, shadowing, and a working WhatsApp exfiltration through hidden `<IMPORTANT>` blocks in tool descriptions (citations below). `mcp-gateway` is a single Rust binary that sits between the agent and every backend, and:

- Exposes a **compact Meta-MCP surface** (12–15 tools) instead of the raw N-server fanout. ~91% token savings at 100 tools / 1000 requests, measured in `benchmarks/public_claims.json`.
- Runs every backend tool description through a validator before it hits the agent's context. Rule **AX-010** (`src/validator/rules/tool_poisoning.rs`, 19 tests) catches the Invariant patterns: `<IMPORTANT>` tags, `~/.ssh`/`id_rsa`/`.env`/`/etc/passwd` paths, "sidenote" exfiltration, curl-to-HTTP, base64 in exfil context, zero-width and bidi-override Unicode.
- Hash-pins capability YAMLs by SHA-256 and fail-closes on any post-load mutation (`RUG-PULL DETECTED`).
- Imports a full OpenAPI spec into validated capability YAMLs with one command (Petstore: 19 operations end-to-end).

2888 tests passing, `#![deny(unsafe_code)]`, zero clippy warnings, ~8 ms startup. MIT. This is the most mature of the four repos and is what I planned to Show HN'd a week ago. Then I kept building.

### Repo 2 — `botnaut-client` (the agent)

A hard-fork of [Goose v1.30.0](https://github.com/block/goose) hardened into a coding agent I actually trust to run unattended on my own work:

- **Hook system** — 8 Claude-Code-compatible events (`PreToolUse`, `PostToolUse`, `SessionStart`, etc.). Hooks are JSON-over-stdin, language-agnostic, and fail-closed: any unhandled exception in a hook blocks the tool call.
- **YAML-frontmatter skills** ported from my own claude-elite rules tree. Skills are auto-discovered and route by keyword, not by "tell Claude to invoke the skill", so they compose.
- **Two-pass plan mode** — draft a plan, show it, require approval, then execute. Wired into the live agent loop (not a separate CLI).
- **Constitutional gate wired as a `PreToolUse` hook** — every tool call flows through a deny-by-default policy before execution. More on this below.
- **hebb + metacognition as default MCP extensions** — persistent memory and reasoning verification are on by default, not an afterthought.
- 1155+ tests passing across 5 crates.

Public: https://github.com/MikkoParkkola/botnaut-client. License PolyForm-Noncommercial + commercial ping.

### Repo 3 — formally verified constitutional compliance (`botnaut/formal/`)

The gate the hook calls is not a regex list. It's a four-principle constitutional policy with:

- **Ed25519 receipt chain** over every verdict (`hash-linked JSONL audit at ~/.botnaut/audit/constitutional_audit.jsonl`).
- **Owner-pinned signing** with a key-ceremony script.
- **TLA+ spec** of the amendment protocol with six invariants (`formal/Amendment.tla`, 281 lines): non-dilution, owner primacy, attestation chain, non-equivocation, liveness, safety under failure.
- **Z3 proof** (`formal/enforcement_proof.py`, 402 lines) of five runtime properties: **P1 deny-by-default, P2 fail-closed on invalid signature, P3 receipt-chain integrity, P4 monotonic audit, P5 deny-precedence.** All five currently proved (UNSAT on negation).
- `strict_mode=True` is the production default, wired through the hook (`BOTNAUT_STRICT_MODE` env var).

As far as I can tell this is the first open-source combination of Ed25519 receipt chain + TLA+ invariants + Z3 enforcement properties applied to an LLM agent's tool-use gate. Patent claim drafted (I-020), not filed.

### Repo 4 — MetaThinker (the meta-thinker)

This is the one I'm least ready to publish and most excited about. `docs/design/metathinker.md` (1139 lines) specs a **fine-tuned small model** whose job is to conduct a bounded, multi-turn Socratic dialogue with a larger model — not as a one-shot critic, but across named techniques with convergence detection:

- 12 named critical-thinking techniques: **Devil's Advocate, ACH (Analysis of Competing Hypotheses), Socratic, Pre-mortem, Steelman, Occam, First-Principles, Base-Rate, Fermi, Counterfactual, Confirmation-Bias Check, Temporal.** Each carries origin, category, system prompt, and known failure modes.
- Rust + Python prompt-template parity (`crates/metacognition-core/src/techniques/mod.rs`, 856 lines), 45 tests guarding that both implementations emit byte-identical prompts.
- `challenge_reasoning` MCP tool stub — schema is frozen; the fine-tuned model weights are not.
- 9 draft patent claims (I-021): first fine-tuned meta-thinker that conducts a bounded multi-turn dialogue with a technique curriculum and a convergence detector.

What's shipped is the prompt library and the MCP schema. What's not shipped is the trained model. Call it scaffolding in search of a checkpoint.

### Bonus — HIGGS 3-bit quantization

Because the stack needs to run locally to mean anything, `botnaut-engine` now has a HIGGS offline quantizer (Phase 1, 814 LOC of FWHT + lattice code) and a runtime CUDA GEMV kernel (Phase 2, `patches/higgs_gemv.cu`, 432 LOC). Writer + reader for the `projections_higgs.bin` format is 929 LOC. **Asymmetric bit allocation: 3-bit DeltaNet, 4-bit full-attention layers** — because DN is recurrent, so quantization error doesn't accumulate the same way. Patent claim I-019 drafted, not filed. This is in-progress: format is frozen, kernel compiles, full round-trip integration is the next milestone.

### What's real vs scaffolding

Honesty matters more than a punchy title:

- **Shipped and runs**: mcp-gateway (2888 tests, MIT), botnaut-client (1155+ tests, public), formal proofs (Z3 PROVED × 5, TLA+ spec reviewable).
- **Scaffolded, frozen schema, not trained**: MetaThinker.
- **Partially integrated**: HIGGS Phase 2 kernel (compiles, not yet swapped into the hot path), Mojo gradient firewall (Phase 1 skeleton + Rust FFI wrapper, 11 tests).
- **Not published**: patent filings (drafted), demo video.

33 commits across 7 repos this week. I'm not claiming any of this is production for your company — I'm claiming it's the first stack where the alignment decision is **formally verifiable** rather than asserted, and where every layer from the protocol boundary to the critic is mine (or forkable).

### What I want from HN

Break it. Specifically:
1. Find a tool-poisoning payload AX-010 misses.
2. Find a Z3 countermodel for any of the five enforcement properties.
3. Find a TLA+ invariant I missed in the amendment protocol.
4. Tell me what a sovereign coding-agent stack should include that I haven't built yet.

Repos:
- https://github.com/MikkoParkkola/mcp-gateway (MIT, ready)
- https://github.com/MikkoParkkola/botnaut-client (PolyForm-Non-commercial, public)
- `botnaut/` (proprietary, formal proofs reproducible — see `formal/README.md`)
- `metacognition/` (MetaThinker, design + scaffolding public)

Stack: Rust 1.88 edition 2024, Python 3.12+ for the gate, Z3 for enforcement, TLA+ for the amendment protocol, CUDA 13.2 for HIGGS.

Citations:
- Invariant Labs, tool-poisoning: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
- Invariant Labs, WhatsApp MCP exploit: https://invariantlabs.ai/blog/whatsapp-mcp-exploited
- Simon Willison on MCP prompt-injection: https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/

Happy to answer questions.
