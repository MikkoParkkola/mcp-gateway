# Hebb Factual Recall Compensation for 1-bit Models

**Ticket:** MIK-2753 (spike) | **Status:** Research | **Date:** 2026-05-19
**Owner:** mcp-gateway × hebb | **Bet:** B2-MEM (universal context default)

## 1. Problem: the 1-bit model factual-recall gap

1-bit / ternary LLMs (BitNet b1.58, BitNet a4.8, Microsoft 2B/3B BitNet, 2024-2025
ternary Llama variants) deliver 4-10x inference cost reduction and 5-7x memory
footprint reduction, but exhibit a measurable **factual-recall quality gap**
versus fp16/bf16 peers on knowledge-heavy benchmarks (TriviaQA closed-book,
PopQA tail entities, NaturalQuestions long-tail, MMLU sub-domains with rare
facts). Reported gaps in literature: 4-12 points absolute accuracy on tail
facts; near-parity on reasoning/code benchmarks. The gap is **knowledge-shaped,
not reasoning-shaped** — quantization preferentially destroys low-frequency
parametric memory, not circuits.

This makes 1-bit attractive for cost but unsafe to ship as a drop-in for
RAG/agent workloads where factual precision matters (tool routing, citation,
identity attribution, legal/medical lookups).

## 2. Hypothesis: hebb closes the gap at retrieval, not at training

**H1 (primary):** Pairing a 1-bit base model with a high-quality retrieval
memory layer (hebb: BGE-M3 1024d embeddings, HNSW+BM25+RRF, surprisal-gated
writes) recovers >=80% of the fp16 factual-recall gap at <=15% added
end-to-end latency, **without** any retraining or QAT adjustment of the 1-bit
model.

**H2 (mechanism):** The 1-bit model retains reasoning + composition circuits;
hebb supplies the missing tail-fact tokens as in-context evidence. The model's
job degrades from "recall + reason" to "reason over retrieved evidence" — the
half of the task it is still good at.

**H3 (economic):** A 1-bit + hebb stack delivers fp16-class factual accuracy
at 25-40% of the fp16 total cost-of-inference (compute + memory + retrieval
overhead amortised), making it the **dominant** point on the cost/quality
frontier for knowledge-grounded agent workloads.

**Why hebb specifically (not generic RAG):** BGE-M3 multi-vector retrieval
beats single-vector dense on tail entities (LoCoMo #1, 2025); surprisal-gated
writes mean the index naturally concentrates on the exact low-frequency facts
that quantization eats; RRF fusion is robust to query-side noise from a weaker
1-bit query encoder.

## 3. Experiments (3-5)

### E1 — Gap characterization (baseline, ~1 day)
Measure factual-recall delta on a fixed eval set:
- **Models:** BitNet b1.58 3B vs Llama-3.2 3B bf16 (matched-size pair); add
  BitNet 2B (Microsoft, 2025) vs Phi-mini 3.8B as second pair.
- **Evals:** PopQA (tail-entity slice), TriviaQA closed-book, NaturalQuestions
  short-answer, MMLU sub-domains (history/geography/biology — fact-heavy).
- **Output:** per-benchmark accuracy delta, broken down by entity frequency
  bucket. **Expected:** 4-12pt gap concentrated in low-frequency buckets.
- **Pass:** delta measured to ±1pt; frequency-bucket curve plotted.

### E2 — Hebb-retrieval compensation (core test, ~2 days)
Pre-index Wikipedia + relevant knowledge corpus into hebb. At inference,
prepend top-k retrieved chunks to the 1-bit model's context.
- **Conditions:** 1-bit base | 1-bit + hebb(k=3) | 1-bit + hebb(k=8) |
  fp16 base | fp16 + hebb(k=3).
- **Metric:** accuracy recovery ratio = (1bit+hebb - 1bit) / (fp16 - 1bit).
- **Pass:** ratio >=0.80 on PopQA tail, >=0.70 on TriviaQA, with <=15%
  latency overhead vs 1-bit alone.

### E3 — Retriever-quality ablation (~1 day)
Hold 1-bit base constant, vary retrieval quality:
- BM25-only | BGE-M3 dense-only | BGE-M3 multi-vector | hebb full (HNSW+BM25+RRF).
- **Hypothesis:** recovery ratio scales with retrieval quality; hebb full
  >= BGE-M3 multi-vector > dense-only > BM25-only.
- **Pass:** strict ordering observed; hebb full wins by >=3pt over single-mode.

### E4 — Surprisal-gated index efficiency (~1 day)
Compare full Wikipedia index vs surprisal-gated subset (top 30% by hebb's
surprisal score, which favours rare/novel content).
- **Hypothesis:** gated index retains >=95% of accuracy at 30% storage —
  precisely because the rare facts that 1-bit forgets are the facts surprisal
  preferentially keeps.
- **Pass:** accuracy retention >=95% at <=35% index size.

### E5 — Total-cost-of-inference frontier (synthesis, ~1 day)
Build the cost/quality scatter for an agent workload (gateway tool-routing
trace, 10k queries):
- Axes: $/1k queries (compute + retrieval + memory amortised) vs factual
  accuracy.
- Points: 1-bit | 1-bit+hebb | fp16 | fp16+hebb | fp8+hebb.
- **Pass:** 1-bit+hebb sits on the Pareto frontier and dominates fp16-alone
  on both axes (cheaper AND more accurate, because fp16 still has tail-fact
  gaps without retrieval).

## 4. Risks & kill-criteria

- **R1:** 1-bit query-side encoding too weak → retrieval relevance collapses.
  *Mitigation:* use fp16 encoder for query embedding only (hebb side); 1-bit
  only for generation. Cost still favourable.
- **R2:** Context-length overhead negates 1-bit memory savings. *Mitigation:*
  measure at k=3 first; if k>=8 needed, reconsider.
- **Kill:** if E2 recovery ratio <0.50, hypothesis dies — gap is circuit-level,
  not memory-level, and retrieval cannot fix it.

## 5. Acceptance criteria (spike DoD)

- [x] Gap thesis articulated with model+benchmark specificity (§1)
- [x] Hypothesis stated with measurable predictions (§2, H1-H3)
- [x] >=3 experiments with pass/fail thresholds (§3, E1-E5)
- [x] Kill criteria defined (§4)
- [x] Maps to portfolio bet B2-MEM (universal context default)

## 6. Next step

Promote E1+E2 to a 1-week implementation ticket if spike is accepted.
Owner pairing: hebb (retrieval) + nvfp4-mojo or external BitNet checkpoint
(1-bit base). Eval harness lives in `~/github/hebb/benches/factual-recall/`.
