# The sovereign coding-agent stack — a two-week status report

Author: Mikko Parkkola
Date: 2026-04-12
Status: Draft for launch

## TL;DR

"Sovereign" is overloaded. In this post it means one thing: **every layer of the coding-agent stack is either mine or forkable, and the alignment decision is formally verifiable rather than asserted.** Over the last two weeks I shipped 33 commits across 7 repos toward that target. This post walks through what's in the stack, what's proven, what's scaffolding, and why I think the frame matters now.

The stack, top to bottom:

1. **[mcp-gateway](https://github.com/MikkoParkkola/mcp-gateway)** — the protocol boundary. Single Rust binary, compact Meta-MCP surface (12–15 tools), tool-poisoning validator, hash-pinned capability YAMLs. MIT. 2888 tests.
2. **[botnaut-client](https://github.com/MikkoParkkola/botnaut-client)** — the agent. Hard-fork of Goose v1.30.0 with Claude-Code-compatible hooks, YAML-frontmatter skills, two-pass plan mode, and a constitutional gate wired as `PreToolUse`. PolyForm-Non-commercial. 1155+ tests.
3. **Constitutional compliance (`botnaut/formal/`)** — the alignment gate. Ed25519 receipt chain, TLA+ spec with 6 invariants, Z3 proofs of 5 runtime properties, owner-pinned signing, strict deny-by-default. Formally verified today.
4. **MetaThinker (`metacognition/`)** — the meta-thinker. Fine-tuned-model design for bounded multi-turn Socratic dialogue across 12 named critical-thinking techniques. Prompt library and MCP schema shipped; checkpoint not yet trained.
5. **HIGGS quantization (`botnaut-engine/`)** — the numerics. Offline quantizer + runtime CUDA GEMV kernel, asymmetric 3-bit/4-bit allocation between DeltaNet and full-attention layers.

None of these requires any of the others. That's the point. You can take mcp-gateway and run it in front of Claude Code today; you can take botnaut-client and point it at any OpenAI-compatible backend; you can take the Z3 proofs and re-run them against your own gate implementation. What the stack buys you is the **composition**: the agent's every tool call passes through a gate whose correctness is machine-checkable, whose decisions are cryptographically chained, and whose protocol boundary is audited text you can `grep` in a PR.

---

## 1. Why "sovereign" is a technical term this year, not a political one

Every coding-agent product today is a thin orchestration layer. The layers underneath — model API, tool-call protocol, alignment policy, observability — all belong to someone else. This is fine until it isn't:

- **Protocol shifts.** MCP's `tools/list` is untrusted text the agent will read. That's not a bug in any one server; it's a property of the topology. Invariant Labs showed that one poisoned server exfiltrates WhatsApp chat history through a hidden `<IMPORTANT>` block.
- **API shifts.** Anthropic's rate-limit crisis on 2026-04-07 had 4 of 5 parallel agents returning `429` within seconds. Your agent's reliability is a vendor decision.
- **Alignment shifts.** You cannot prove that a system prompt containing "be helpful, harmless, honest" enforces anything. It's a suggestion.

"Sovereign" here means: **I can reproduce every bit of the stack from source, and the alignment gate ships with a proof, not a prompt.**

## 2. mcp-gateway — one audit surface for N servers

The detailed version of this lives in `docs/blog/security-aware-mcp-gateway.md` — what follows is the abbreviated story.

An agent that sees every tool description from every server is one poisoned server away from compromise. mcp-gateway replaces the direct topology with a Meta-MCP surface (12–15 meta-tools like `gateway_list_tools`, `gateway_search_tools`, `gateway_invoke`). The agent never reads raw backend descriptions. Every description flows through `src/validator/rules/tool_poisoning.rs` — rule AX-010, 19 tests — which catches the Invariant patterns (paths to secrets, `<IMPORTANT>` markers, sidenote exfiltration, curl-to-HTTP, base64 in exfil context, bidi/zero-width Unicode).

Capability YAMLs are SHA-256 pinned. A post-load mutation trips `RUG-PULL DETECTED` and the capability is quarantined. The hash is reproducible from a shell (`grep -v '^sha256:' cap.yaml | sha256sum`) so reviewers can verify the pinned file is what they reviewed.

Numbers, all from the repo:

- 2888 tests, `#![deny(unsafe_code)]`, zero clippy warnings
- ~91% token savings at 100 tools / 1000 requests (`benchmarks/token_savings.py`)
- ~8 ms startup (`hyperfine`, `docs/BENCHMARKS.md`)
- 101 built-in REST capabilities across 16 categories

**What's shipped:** everything above. MIT. Binary is ~12 MB.

## 3. botnaut-client — a coding agent I trust to run unattended

This started as "let's see what a sovereign Goose fork looks like" and ended as a distinct agent. From the commit log since the fork on 2026-04-12:

- `feat(hooks): Claude-Code-compatible hook system` — 8 events (`SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `SubagentStop`, `Stop`, `Notification`, `PreCompact`), JSON-over-stdin, language-agnostic.
- `feat(mcp): hebb + metacognition shipped as default extensions` — persistent memory (hebb) and reasoning verification (metacognition) are on by default from the first run. Seeded from `init-config.yaml` only if the user has no config yet; user config wins.
- `feat(skills): YAML frontmatter skills system ported from claude-elite` — skills auto-discovered by keyword, so they compose rather than requiring the agent to know their names.
- `feat(plan-mode): two-pass execution with approval gate` and `feat(plan-mode): wire PlanModeController into live agent loop` — draft, approve, execute. Wired into the live loop, not a separate CLI mode.
- `feat(constitutional): wire Python gate as PreToolUse hook` and `config(hooks): enable strict_mode=True in constitutional gate hook` — every tool call passes through the gate described in §4.

The hook contract is tiny:

```json
// stdin
{ "event": "PreToolUse", "tool_name": "Bash",
  "tool_arguments": {"cmd": "…"},
  "session_id": "…", "extra": null }

// stdout
{ "continue": true, "output": "reason", "decision": "approve" }
```

Any unhandled exception in a hook exits non-zero, which the runner interprets as **unconditional block**. That's the fail-closed contract.

1155+ tests passing across 5 crates (`botnaut-core`, `botnaut-cli`, `botnaut-mcp`, `botnaut-test`, `botnaut-test-support`). The CLI binary is `botnaut`. Public at https://github.com/MikkoParkkola/botnaut-client. License: PolyForm-Noncommercial 1.0.0 with commercial ping.

**What's shipped:** everything above. UI decision still pending (entropy-sweep doc).

## 4. Constitutional compliance — the part with proofs

This is the piece I think most about. The hook in §3 is the front-end; the policy behind it is the part nobody else in the coding-agent space (as far as I can tell) ships.

### 4.1 Receipt chain

Every verdict is an Ed25519-signed record with a `prev_hash` field. The audit log at `~/.botnaut/audit/constitutional_audit.jsonl` is append-only JSONL; each line's `prev_hash` is `SHA-256(previous_content)`. A Z3 property (P3) proves that for all `i ∈ 1..5`, `prev_hash[i] == SHA256(content[i-1])` — i.e. that a bounded chain of five records is internally consistent by construction.

### 4.2 TLA+ spec of the amendment protocol

The constitution itself can be amended, but only through a protocol modelled in `formal/Amendment.tla` (281 lines). The state machine is:

```
Draft ─Propose─▶ Proposed ─OwnerSign─▶ Signed ─Apply─▶ Applied
                      ╲_NonOwnerSign_▶ Rejected
                      ╲_FailDuringSign_▶ (no state change)
                      ╲_FailDuringApply_▶ (no state change)
```

Six invariants checked by TLC:

1. **Type invariant** (structural)
2. **NonDilution** — non-owner votes cannot amend
3. **OwnerPrimacy** — only owner signatures transition Proposed → Signed
4. **AttestationChain** — every Applied amendment has an intact signature chain
5. **NonEquivocation** — the same version cannot be Applied twice with different content
6. **SafetyDuringFailure** — a failure mid-sign or mid-apply leaves the state machine in a valid prior state

Plus a **Liveness** property: any Proposed amendment eventually reaches Applied or Rejected.

TLC runs in ~30 s for the bounded model (three amendments, two non-owners, max version 3) and reports all invariants hold.

### 4.3 Z3 enforcement proof

`formal/enforcement_proof.py` (402 lines) encodes the verdict-resolution lattice of the runtime gate as Z3 constraints and tries to falsify each property. UNSAT on every negation = property proved. Current output:

```
[PROVED] P1 deny-by-default        — no permit rule ⇒ verdict ≠ ALLOW
[PROVED] P2 fail-closed signature  — invalid sig ⇒ verdict == ERROR
[PROVED] P3 receipt-chain integrity — prev_hash[i] == SHA256(content[i-1]) ∀ i ∈ 1..5
[PROVED] P4 monotonic audit        — |audit[t+1]| ≥ |audit[t]| over 8 ticks
[PROVED] P5 deny-precedence        — matched DENY ⇒ verdict == DENY
Total: 5   Proved: 5   Counterexamples: 0
```

The Python gate is the **source of truth**: if a proof fails, the Python is what the spec must match, not the other way around. The artefact's job is to surface latent divergence, not to drive the code from the spec.

### 4.4 What this buys vs a regex gate

- **Regex gates fail silently.** Add a rule, forget to add the corresponding test, someone else refactors, the rule stops firing. No alert.
- **Proved gates fail loudly.** If someone refactors the Python and P1 becomes falsifiable, CI goes red on the Z3 run. The proof is a living assertion about the running code.
- **Receipt chains audit the past.** Regex gates tell you what happened now. A hash-linked audit lets a reviewer verify that the sequence of verdicts is internally consistent three months later.

This is, as far as I can tell, the first open-source combination of (a) Ed25519 receipt chain + (b) TLA+ invariants on the amendment protocol + (c) Z3 enforcement properties, applied to an LLM agent's tool-use gate. Patent claim drafted (I-020), not filed.

**What's shipped:** all four sub-items above. The proofs run. The TLA+ spec is reviewable without TLC installed (self-contained).

## 5. MetaThinker — a fine-tuned critic with a convergence detector

This is design-dominant; I want to flag that up front.

The design doc (`docs/design/metathinker.md`, 1139 lines) specs a 3B–7B fine-tuned model that conducts a **bounded multi-turn Socratic dialogue** with a larger model's answer. Each turn applies one of 12 named critical-thinking techniques. The dialogue ends when the critique converges (no new concerns surface across two consecutive techniques) or when a step budget is hit.

The 12 techniques, each with origin, category, system prompt, and known failure modes:

1. **Devil's Advocate** (assumption challenge)
2. **ACH — Analysis of Competing Hypotheses** (Heuer, CIA 1999; causality)
3. **Socratic** (derivation)
4. **Pre-mortem** (Klein 2007; bias toward overconfidence)
5. **Steelman** (scope — strongest counter-position)
6. **Occam's razor** (complexity)
7. **First-principles** (derivation)
8. **Base-rate** (Tversky/Kahneman; magnitude)
9. **Fermi estimation** (magnitude)
10. **Counterfactual** (causality)
11. **Confirmation-bias check** (bias)
12. **Temporal** (scope — has context changed?)

Why a fine-tuned model instead of prompt-engineering a big one? Three reasons:

- **Cost.** Running 12 technique turns through GPT-4 is untenable at interactive latency. A 3B model at 200 tok/s on consumer hardware is not.
- **Consistency.** SFT on the technique prompts + RLHF on convergence quality gives a model that *actually* stays inside the technique's scope across turns. Zero-shot LLMs drift within 2 turns.
- **Proprietary output schema.** The critic emits strict JSON (`verdict: ACCEPT|REFINE|ESCALATE`, `critique`, `suggested_revision`), which is unforgiving territory for generalist models.

The MCP surface is a single tool, `challenge_reasoning`, with frozen schema. The Rust + Python prompt-template libraries (`crates/metacognition-core/src/techniques/mod.rs`, 856 lines) share 45 parity tests that guarantee byte-identical prompts across languages.

9 draft patent claims (I-021): first fine-tuned meta-thinker that conducts a bounded multi-turn dialogue with a technique curriculum and a convergence detector, with provenance attribution for each technique's critique.

**What's shipped:** prompt library, MCP schema, 45 parity tests, challenge_reasoning stub. **What's not:** the checkpoint. Fine-tune is next.

## 6. HIGGS — asymmetric quantization for hybrid architectures

Brief, because it's an optimization layer, not a thesis. botnaut-engine's model is **Qwen3.5-35B-A3B** — 40 layers, 10 full-attention, 30 DeltaNet (O(1) recurrent linear attention). Quantization hits those layers differently:

- **Full-attention layers** accumulate state through the KV cache. Quantization error at layer N propagates to every subsequent token that reads those K/V slots. 3-bit here would be painful.
- **DeltaNet layers** are recurrent with a decaying state; errors attenuate over the half-life (tens to thousands of tokens depending on the head). 3-bit is tolerable.

So: **3-bit DN, 4-bit FA.** The offline quantizer (Phase 1, `tools/bnaut-convert/src/higgs.rs`, 814 LOC) does Fast Walsh-Hadamard Transform rotation + lattice quantization. The runtime CUDA GEMV kernel (Phase 2, `patches/higgs_gemv.cu`, 432 LOC) reads the quantized projections without dequantizing. Writer/reader for the `projections_higgs.bin` format is `higgs_writer.rs` (929 LOC).

Patent claim I-019: asymmetric bit allocation between recurrent and non-recurrent layers in a hybrid linear/full-attention architecture.

**What's shipped:** Phase 1 quantizer runs, Phase 2 kernel compiles. **In-progress:** end-to-end round-trip through the production decode loop, quality measurement vs BQ4 baseline.

## 7. What's NOT in the stack (honestly)

I would rather be up-front about the gaps than oversell:

- **No demo video yet.** Showing a one-minute reel of the constitutional gate denying a tool call is an obvious next step and it doesn't exist.
- **MetaThinker has no trained checkpoint.** The design is detailed; the artefact is 12 prompt templates and an MCP schema.
- **HIGGS is mid-integration.** Kernel compiles; not yet swapped into the hot path.
- **No runtime output sanitization for MCP responses.** Prompt injection via tool results (Simon Willison's point) is a separate threat than tool-poisoning and isn't fixed structurally yet. There's a pattern-based response inspector in mcp-gateway (`src/security/response_inspect.rs`) that catches known tricks, but structured output contracts are the real fix and they're on the roadmap.
- **Upstream MCP hash-pinning needs a spec extension.** I can hash-pin capability YAMLs; I can't hash-pin a stdio MCP server's `tools/list` response without the protocol agreeing.
- **No patent filings yet.** Three claims drafted (I-019, I-020, I-021), none filed. This is tracked.
- **Mojo gradient firewall is Phase 1 skeleton.** The 607-line design doc exists; the Rust FFI wrapper crate exists with 11 tests; the actual gradient-firewall Mojo code is stubs.

## 8. Why build this instead of using opencode / Aider / Cursor?

The honest answer is I use Claude Code every day and it's great. This stack is not trying to replace Claude Code for my daily work. It's trying to answer a different question: **if a small team wanted to run a coding agent on a hostile network, on proprietary code, with an alignment gate they can audit, what would the stack look like?**

Aider owns the CLI loop. Cursor owns the IDE. opencode owns the fork. None of them own the alignment decision or the protocol boundary. When your threat model includes the MCP ecosystem, the prompt-injection class, and a desire to prove (not assert) that your agent won't delete your `~/.ssh`, you need different primitives. Those primitives are what I've been building.

## 9. What I want from you

Break it. Specifically:

1. Find a tool-poisoning payload AX-010 misses. PR welcome.
2. Find a Z3 countermodel for any of P1–P5. I will buy you a beer.
3. Find an invariant the TLA+ amendment protocol doesn't cover.
4. Tell me what a sovereign coding-agent stack should include that I haven't built yet.

## Source pointers

- Tool-poisoning rule: `mcp-gateway/src/validator/rules/tool_poisoning.rs` (19 tests)
- Capability hash: `mcp-gateway/src/capability/hash.rs` (8 tests)
- Hook system: `botnaut-client/crates/botnaut-core/src/agents/hooks.rs` + `examples/hooks/constitutional.json`
- Constitutional hook adapter: `botnaut-client/hooks/constitutional_gate.py` (266 LOC)
- TLA+ spec: `botnaut/formal/Amendment.tla` (281 LOC) + `Amendment.cfg`
- Z3 proof: `botnaut/formal/enforcement_proof.py` (402 LOC)
- MetaThinker techniques: `metacognition/crates/metacognition-core/src/techniques/mod.rs` (856 LOC)
- MetaThinker design: `metacognition/docs/design/metathinker.md` (1139 LOC)
- HIGGS quantizer: `botnaut-engine/tools/bnaut-convert/src/higgs.rs` (814 LOC)
- HIGGS kernel: `botnaut-engine/patches/higgs_gemv.cu` (432 LOC)

## Citations

- Invariant Labs, tool-poisoning: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
- Invariant Labs, WhatsApp MCP exploited: https://invariantlabs.ai/blog/whatsapp-mcp-exploited
- Simon Willison, "MCP has prompt injection security problems": https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/
- Leslie Lamport, TLA+: https://lamport.azurewebsites.net/tla/tla.html
- Leonardo de Moura, Z3: https://github.com/Z3Prover/z3
- Richards J. Heuer, "Analysis of Competing Hypotheses", CIA 1999
- Gary Klein, "Performing a Project Premortem", HBR 2007
