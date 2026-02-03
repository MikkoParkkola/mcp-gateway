# MCP Gateway Benchmarks

Last updated: 2026-02-03

## Build Information

| Metric | Value |
|--------|-------|
| Rust Version | 1.85+ (Edition 2024) |
| Binary Size | 7.1 MB (release) |
| Source Files | 38 Rust files |
| Lines of Code | 6,714 |
| Test Count | 55 (unit + integration) |

## Startup Performance

```
$ hyperfine --shell=none --warmup 3 --runs 20 'target/release/mcp-gateway --help'

Benchmark: target/release/mcp-gateway --help
  Time (mean ± σ):       8.0 ms ±   1.2 ms
  Range (min … max):     5.4 ms …   9.7 ms
```

**Startup time: ~8ms** - Fast enough for CLI and server use.

## Memory Usage

TBD - Run under production load

## Request Latency

TBD - With actual backend connections

## Comparison

| Gateway | Startup | Binary Size | Language |
|---------|---------|-------------|----------|
| mcp-gateway | ~8ms | 7.1MB | Rust |
| (Node.js equiv) | ~100ms | N/A | TypeScript |

## Running Benchmarks

```bash
# Build release
cargo build --release

# Startup time
hyperfine --shell=none --warmup 3 'target/release/mcp-gateway --help'

# Code stats
scc . --exclude-dir target --exclude-dir .git
```
