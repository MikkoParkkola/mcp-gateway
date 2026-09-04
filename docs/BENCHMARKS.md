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
| Live agent task cost | no measured saving in this 16-run sample; the meta path used 1.3–16.1% more input tokens | `benchmarks/results/mik-6977-live-agent-2026-09-04.json` |
| Schema-only model | 100 tools → ~1600 gateway schema tokens → 89% smaller first request; not completed-task cost | `python benchmarks/token_savings.py --scenario readme` |

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
eight tasks.

| Permitted tools | Direct total task tokens | Meta total task tokens | Meta input-token saving | Direct / meta median latency | Extra meta turns |
|---:|---:|---:|---:|---:|---:|
| 50 | 70,211 | 81,593 | -16.08% | 15.1s / 21.3s | 1 |
| 100 | 79,949 | 85,638 | -7.11% | 15.6s / 20.1s | 1 |
| 200 | 80,358 | 81,676 | -1.47% | 18.3s / 21.9s | 1 |
| 500 | 80,505 | 81,566 | -1.26% | 15.3s / 21.7s | 1 |

This result does not support a completed-task token-savings claim. The meta
surface added a search call and one turn. It was 3.6–6.3 seconds slower in this
small sample.
It remains useful as a catalog-capacity boundary, but we do not lead with the
schema-only 89% model as a task result.

The benchmark is deliberately narrow. It uses one agent and model with two
trials per cell. The tools are generated around an exact numeric target, and
there is no real backend latency. Total task tokens include the Codex host
context. Use the checked-in per-trial artifact to inspect the measurements; do
not generalize them to other models or workloads.

```bash
python benchmarks/live_agent_tool_selection.py \
  --sizes 50,100,200,500 --trials 2 --jobs 4 \
  --output-json benchmarks/results/mik-6977-live-agent-2026-09-04.json
```

## Schema-only first-request model

```bash
python benchmarks/token_savings.py --scenario readme
python benchmarks/token_savings.py --scenario readme --json
```

Reference scenario assumptions:

- 100 direct tools at ~150 tokens each
- 16 Meta-MCP tools in the README benchmark scenario at ~100 tokens each
- 1,000 requests
- Claude Opus input pricing at $15 / million tokens

The base discovery quartet stays constant, and the README benchmark scenario adds stats, cost report, playbooks, profile controls, disabled-capability listing, and reload. Surfacing webhook status adds the 17th tool.

This yields the schema-only first-request numbers: **~1600 gateway tokens** and **89% smaller**, with a modeled **$201 per 1K requests**. It is not a completed-task saving. Extra discovery turns (`gateway_search_tools` then `gateway_invoke`) reload that surface and carry accumulated discovery responses. The in-tree `honest_task_tokens` model counts both and is allowed to report a loss. `benchmarks/discovery_response_fixture.json` is a synthetic L0 lower-bound fixture with the exact `build_search_response` envelope, not a captured production response. The live run above measures selection and task completion. It also records latency, turns, and task tokens.

With the current 100-token synthetic response fixture, the default completed-task
case at 100 tools is 30,000 eager tokens versus 5,000 gateway tokens (83.3%
savings). The registered 20-extra-turn loss case is 30,000 versus 54,500 tokens
(-81.7% savings).

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
python benchmarks/token_savings.py --scenario readme

# Live agent comparison (requires authenticated Codex CLI access)
python benchmarks/live_agent_tool_selection.py --output-json /tmp/mik-6977-live.json

# Code stats
scc . --exclude-dir target --exclude-dir .git
```
