# MCP Gateway Benchmarks

Public quantitative claims are tracked in [benchmarks/public_claims.json](../benchmarks/public_claims.json) and validated in CI by `tests/public_claims_validation.rs`.

## Build Information

| Metric | Value |
|--------|-------|
| Rust Version | 1.88+ (Edition 2024) |
| Binary Size | ~12-13 MB (release, stripped) |
| Source / test counts | Intentionally not hard-coded here |

## Canonical Public Claims

| Claim | Value | Source |
|------|-------|--------|
| Meta-tools exposed to the AI | 14 minimum / 16 README benchmark / 17 with webhook status | `benchmarks/public_claims.json` |
| Built-in capability YAMLs | 119 total (marketed as 110+) | `benchmarks/public_claims.json` + `find capabilities -name '*.yaml' -not -path '*/examples/*' \| wc -l` |
| Startup time | ~8ms | `hyperfine --shell=none --warmup 3 --runs 20 'target/release/mcp-gateway --help'` |
| Live agent task cost | no measured saving; the meta path cost more input tokens in all 8 matched pairs | `benchmarks/results/mik-6977-live-agent-2026-09-04.json` |
| Schema-only model | 100 tools → ~1600 gateway schema tokens → 89% smaller first request; not completed-task cost | `python3 benchmarks/token_savings.py --scenario readme` |

## Startup Performance

```
$ hyperfine --shell=none --warmup 3 --runs 20 'target/release/mcp-gateway --help'

Benchmark: target/release/mcp-gateway --help
  Time (mean ± σ):       8.0 ms ±   1.2 ms
  Range (min … max):     5.4 ms …   9.7 ms
```

**Startup time: ~8ms** - Fast enough for CLI and server use.

## Live agent result

On 2026-09-04, Codex with `gpt-5.6-luna` retrieved one exact item from generated
catalogs of 50, 100, 200, and 500 permitted tools. Each size had two direct and
two meta-surface trials. Both paths selected the correct tool and completed all
eight tasks. Direct mean total task tokens grew from 70,132 to 79,826 between 50 and 100
tools, then stayed near 80,000 at 200 and 500. The host compacted those larger
lists, so only the 50- and 100-tool rows measure a direct catalog that still
scaled with the configured size.

| Permitted tools | Direct mean total task tokens (range) | Meta mean total task tokens (range) | Meta input-token saving, mean | Direct / meta median latency | Extra meta turns |
|---:|---:|---:|---:|---:|---:|
| 50 | 70,132 (70,085–70,178) | 81,421 (81,360–81,482) | -16.01% | 16.0s / 20.5s | 1 |
| 100 | 79,826 (79,820–79,831) | 81,327 (81,305–81,349) | -1.81% | 14.9s / 21.5s | 1 |
| 200 | 80,252 (80,207–80,297) | 81,667 (81,377–81,957) | -1.56% | 15.6s / 23.4s | 1 |
| 500 | 80,292 (80,256–80,327) | 81,354 (81,328–81,379) | -1.27% | 15.9s / 21.0s | 1 |

This result does not support a completed-task token-savings claim. Across all
tested sizes, the meta surface used 1.3–16.0% more input tokens and added one turn.
It cost more input tokens in all eight matched pairs. The 200- and 500-tool rows
are retained as host-compaction evidence, not as catalog-scaling measurements.
It remains useful as a catalog-capacity boundary, but we do not lead with the
schema-only 89% model as a task result.

The benchmark is deliberately narrow. It uses one agent and model with two
trials per cell; the ranges above show both observations. Four trials ran
concurrently, so the latency values are exploratory. An isolated benchmark MCP
server generated the catalog around an exact numeric target. The mcp-gateway
binary was not in the request path. The direct path exposed all generated tools;
the meta path exposed only
the synthetic `gateway_search_tools` and `gateway_invoke` pair, not the 14–17
tool product surface. Search extracted the requested number and otherwise fell
back to the expected index supplied by the runner. Plugins and apps were
disabled, as were memories and host skill discovery. The recorded warnings note the
under-development flag and shortened skill descriptions. There is no real
backend latency. Total task tokens include the Codex host context. Use the
checked-in per-trial artifact to inspect the measurements; do not generalize
them to other models or workloads.

```bash
python3 benchmarks/live_agent_tool_selection.py \
  --sizes 50,100,200,500 --trials 2 --jobs 4 \
  --output-json benchmarks/results/mik-6977-live-agent-2026-09-04.json
```

## Schema-only first-request model

```bash
python3 benchmarks/token_savings.py --scenario readme
python3 benchmarks/token_savings.py --scenario readme --json
```

Reference scenario assumptions:

- 100 direct tools at ~150 tokens each
- 16 Meta-MCP tools in the README benchmark scenario at ~100 tokens each
- 1,000 requests
- Claude Opus input pricing at $15 / million tokens

The base discovery quartet stays constant, and the README benchmark scenario adds stats, cost report, playbooks, profile controls, disabled-capability listing, and reload. Surfacing webhook status adds the 17th tool.

This yields the schema-only first-request numbers: **~1600 gateway tokens** and **89% smaller**, with a modeled **$201 per 1K requests**. It is not a completed-task saving. Discovery turns (`gateway_search_tools` then `gateway_invoke`) reload the host context and Meta-MCP surface while carrying earlier responses forward.

At 50–100 tools, the direct-path observations imply roughly 24,900–27,500 non-schema host tokens per request. Using 27,000 puts the simple crossover near 107 tools: schema savings must cover both the extra request's host context and its carried discovery output. Catalog compaction invalidates the extrapolation above that boundary.

The in-tree `honest_task_tokens` model therefore requires an explicit host-context size. Its discovery fixture is a synthetic L0 lower bound with the exact `build_search_response` envelope, not a production capture. Run `python3 benchmarks/token_savings.py` to see the checked-in live result, including selection, task completion, latency, turns, and task tokens.

## Memory Usage

TBD - Run under production load

## Request Latency

Workload-dependent. Use your real backend mix for end-to-end latency measurements; synthetic single-number claims are intentionally avoided here.

## Comparison

| Gateway | Startup | Binary Size | Language |
|---------|---------|-------------|----------|
| mcp-gateway | ~8ms | ~12MB | Rust |
| (Node.js equiv) | ~100ms | N/A | TypeScript |

## Running Benchmarks

```bash
# Build release
cargo build --release

# Startup time
hyperfine --shell=none --warmup 3 'target/release/mcp-gateway --help'

# README token-savings scenario
python3 benchmarks/token_savings.py --scenario readme

# Live agent comparison (requires authenticated Codex CLI access)
python3 benchmarks/live_agent_tool_selection.py --output-json /tmp/mik-6977-live.json

# Code stats
scc . --exclude-dir target --exclude-dir .git
```
