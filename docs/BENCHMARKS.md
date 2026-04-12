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
| Meta-tools exposed to the AI | 12 minimum / 14 README benchmark / 15 with webhook status | `benchmarks/public_claims.json` |
| Built-in capability YAMLs | 101 total (marketed as 100+) | `benchmarks/public_claims.json` + `find capabilities -name '*.yaml' -not -path '*/examples/*' \| wc -l` |
| Startup time | ~8ms | `hyperfine --shell=none --warmup 3 --runs 20 'target/release/mcp-gateway --help'` |
| README token-savings scenario | 100 tools → ~1400 gateway tokens → **91% savings** | `python benchmarks/token_savings.py --scenario readme` |

## Startup Performance

```
$ hyperfine --shell=none --warmup 3 --runs 20 'target/release/mcp-gateway --help'

Benchmark: target/release/mcp-gateway --help
  Time (mean ± σ):       8.0 ms ±   1.2 ms
  Range (min … max):     5.4 ms …   9.7 ms
```

**Startup time: ~8ms** - Fast enough for CLI and server use.

## README Token-Savings Scenario

```bash
python benchmarks/token_savings.py --scenario readme
python benchmarks/token_savings.py --scenario readme --json
```

Reference scenario assumptions:

- 100 direct tools at ~150 tokens each
- 14 Meta-MCP tools in the README benchmark scenario at ~100 tokens each
- 1,000 requests
- Claude Opus input pricing at $15 / million tokens

The base discovery quartet stays constant, and the always-on operator surface also includes cost report, playbooks, kill/revive controls, profile set/get/list, and disabled-capability listing for a 12-tool minimum. The README benchmark scenario adds stats and reload. Surfacing webhook status adds the 15th tool.

This yields the README headline numbers: **~1400 gateway tokens**, **91% savings**, and **$204 saved per 1K requests**.

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

# Code stats
scc . --exclude-dir target --exclude-dir .git
```
