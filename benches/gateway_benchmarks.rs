//! Criterion benchmark suite for MCP Gateway hot paths.
//!
//! Covers:
//! - Tool registry: O(1) hash lookup, bulk insert, miss path
//! - Simhash: fingerprint computation, Hamming distance, index query
//! - Cache key: SHA-256 derivation, stable tool ordering, schema fingerprint
//! - McpFrame: JSON parsing for request / response / notification frames
//! - SandboxEnforcer: per-invocation policy checks (allowed, denied, expired)

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

use mcp_gateway::{
    cache_key::{CacheKeyDeriver, stable_tool_order, tool_schema_fingerprint},
    protocol::Tool,
    session_sandbox::{SandboxEnforcer, SessionSandbox},
    simhash::{SimhashIndex, hamming_distance, simhash},
    tool_registry::ToolRegistry,
    transport::McpFrame,
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_tool(name: &str) -> Tool {
    Tool {
        name: name.to_string(),
        title: None,
        description: Some(format!("Benchmark tool {name}")),
        input_schema: json!({"type": "object", "properties": {"arg": {"type": "string"}}}),
        output_schema: None,
        annotations: None,
    }
}

/// Build a registry pre-loaded with `n` tools across a single server.
fn filled_registry(n: usize) -> ToolRegistry {
    let reg = ToolRegistry::new(3);
    for i in 0..n {
        reg.insert("bench_server", make_tool(&format!("tool_{i:04}")));
    }
    reg
}

/// Build `n` JSON tool-definition objects for cache-key benchmarks.
fn tool_json_vec(n: usize) -> Vec<Value> {
    (0..n)
        .map(|i| {
            json!({
                "name": format!("tool_{i:04}"),
                "description": format!("Tool number {i}"),
                "inputSchema": {"type": "object", "properties": {}}
            })
        })
        .collect()
}

/// A canonical JSON-RPC request text payload.
const REQUEST_TEXT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"web_search","arguments":{"query":"rust criterion benchmarks"}}}"#;

/// A canonical JSON-RPC response text payload.
const RESPONSE_TEXT: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello world"}]}}"#;

/// A canonical JSON-RPC notification text payload.
const NOTIFICATION_TEXT: &str =
    r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"reason":"refresh"}}"#;

// ── tool_registry benchmarks ──────────────────────────────────────────────────

fn bench_tool_registry(c: &mut Criterion) {
    let mut group = c.benchmark_group("tool_registry");

    // Single insert
    group.bench_function("insert_one", |b| {
        b.iter_batched(
            || ToolRegistry::new(3),
            |reg| {
                reg.insert("srv", make_tool("my_tool"));
            },
            BatchSize::SmallInput,
        );
    });

    // O(1) hash hit across different registry sizes
    for size in [10_usize, 100, 1_000] {
        let reg = filled_registry(size);
        let target = format!("bench_server:tool_{:04}", size / 2);
        group.bench_with_input(BenchmarkId::new("get_hit", size), &target, |b, key| {
            b.iter(|| reg.get(key));
        });
    }

    // Miss path (key not in registry)
    {
        let reg = filled_registry(100);
        group.bench_function("get_miss", |b| {
            b.iter(|| reg.get("bench_server:nonexistent_tool"));
        });
    }

    // Bulk replace_server (refresh a backend's tool list)
    {
        let tools: Vec<Tool> = (0..50).map(|i| make_tool(&format!("tool_{i:04}"))).collect();
        group.bench_function("replace_server_50", |b| {
            b.iter_batched(
                || {
                    let reg = filled_registry(50);
                    (reg, tools.clone())
                },
                |(reg, ts)| reg.replace_server("bench_server", ts),
                BatchSize::SmallInput,
            );
        });
    }

    // contains() check
    {
        let reg = filled_registry(100);
        group.bench_function("contains_hit", |b| {
            b.iter(|| reg.contains("bench_server:tool_0050"));
        });
    }

    group.finish();
}

// ── simhash benchmarks ────────────────────────────────────────────────────────

fn bench_simhash(c: &mut Criterion) {
    let mut group = c.benchmark_group("simhash");

    // simhash() — small and large feature sets
    for count in [4_usize, 16, 64] {
        let features: Vec<String> = (0..count).map(|i| format!("tool_{i}")).collect();
        let feature_refs: Vec<&str> = features.iter().map(String::as_str).collect();
        group.bench_with_input(
            BenchmarkId::new("compute", count),
            &feature_refs,
            |b, feats| b.iter(|| simhash(feats)),
        );
    }

    // hamming_distance — single bit operation
    {
        let a = simhash(&["read_file", "write_file", "list_dir"]);
        let b_hash = simhash(&["read_file", "list_dir", "delete_file"]);
        group.bench_function("hamming_distance", |b| {
            b.iter(|| hamming_distance(a, b_hash));
        });
    }

    // SimhashIndex::find_similar — query against a populated index
    for index_size in [10_usize, 100, 500] {
        let mut idx = SimhashIndex::new();
        for i in 0..index_size {
            let feats: Vec<String> = (0..8).map(|j| format!("tool_{}", i * 8 + j)).collect();
            let refs: Vec<&str> = feats.iter().map(String::as_str).collect();
            idx.insert(format!("session_{i}"), simhash(&refs));
        }
        let query = simhash(&["tool_0", "tool_1", "tool_2", "tool_3"]);
        group.bench_with_input(
            BenchmarkId::new("index_find_similar", index_size),
            &query,
            |b, &q| b.iter(|| idx.find_similar(q, 0.7)),
        );
    }

    group.finish();
}

// ── cache_key benchmarks ──────────────────────────────────────────────────────

fn bench_cache_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_key");

    // from_context: SHA-256 hash of a session-id string
    group.bench_function("from_context", |b| {
        b.iter(|| CacheKeyDeriver::from_context("session-abc-123-def-456"));
    });

    // from_session_and_user: combines two strings then hashes
    group.bench_function("from_session_and_user", |b| {
        b.iter(|| CacheKeyDeriver::from_session_and_user("session-abc", "user-xyz"));
    });

    // from_header: string truncation only (no crypto)
    group.bench_function("from_header", |b| {
        b.iter(|| CacheKeyDeriver::from_header("my-explicit-cache-key-value-here-42"));
    });

    // key_for_slot: format string + modulo
    {
        let deriver = CacheKeyDeriver::with_slots(8);
        group.bench_function("key_for_slot", |b| {
            b.iter(|| deriver.key_for_slot("abc123def456", 3));
        });
    }

    // stable_tool_order — sorting by tool name
    for count in [10_usize, 50, 200] {
        let tools = tool_json_vec(count);
        group.bench_with_input(
            BenchmarkId::new("stable_tool_order", count),
            &tools,
            |b, ts| b.iter(|| stable_tool_order(ts)),
        );
    }

    // tool_schema_fingerprint — BTreeMap + SHA-256 over all schemas
    for count in [10_usize, 50, 200] {
        let tools = tool_json_vec(count);
        group.bench_with_input(
            BenchmarkId::new("schema_fingerprint", count),
            &tools,
            |b, ts| b.iter(|| tool_schema_fingerprint(ts)),
        );
    }

    group.finish();
}

// ── McpFrame parsing benchmarks ───────────────────────────────────────────────

fn bench_mcp_frame(c: &mut Criterion) {
    let mut group = c.benchmark_group("mcp_frame");

    group.bench_function("parse_request", |b| {
        b.iter(|| McpFrame::from_text(REQUEST_TEXT).expect("valid request"));
    });

    group.bench_function("parse_response", |b| {
        b.iter(|| McpFrame::from_text(RESPONSE_TEXT).expect("valid response"));
    });

    group.bench_function("parse_notification", |b| {
        b.iter(|| McpFrame::from_text(NOTIFICATION_TEXT).expect("valid notification"));
    });

    group.bench_function("parse_ping", |b| {
        b.iter(|| McpFrame::from_text(r#"{"type":"ping"}"#).expect("valid ping"));
    });

    group.finish();
}

// ── SandboxEnforcer benchmarks ────────────────────────────────────────────────

fn bench_session_sandbox(c: &mut Criterion) {
    use std::time::Duration;

    let mut group = c.benchmark_group("session_sandbox");

    // Unrestricted sandbox — fastest path (no limit checks skip atomics on max_calls=0)
    {
        let enforcer = SandboxEnforcer::new(SessionSandbox::default());
        group.bench_function("check_unrestricted", |b| {
            b.iter(|| enforcer.check("any_backend", "any_tool", 512).unwrap());
        });
    }

    // All limits set, all passing (full evaluation path).
    // Use iter_batched to get a fresh enforcer each sample — the call counter
    // must not exhaust max_calls across the millions of iterations criterion runs.
    {
        let sandbox = SessionSandbox {
            max_calls: 0, // unlimited, but all other checks are exercised
            max_duration: Duration::from_secs(3600),
            allowed_backends: Some(vec!["allowed_backend".to_string()]),
            denied_tools: vec!["exec".to_string(), "shell".to_string()],
            max_payload_bytes: 65_536,
        };
        group.bench_function("check_all_limits_passing", |b| {
            b.iter_batched(
                || SandboxEnforcer::new(sandbox.clone()),
                |e| e.check("allowed_backend", "web_search", 1024).unwrap(),
                BatchSize::SmallInput,
            );
        });
    }

    // Denied tool path — returns Err on third check (tool denylist)
    {
        let sandbox = SessionSandbox {
            max_calls: 0,
            max_duration: Duration::ZERO,
            allowed_backends: None,
            denied_tools: vec!["forbidden_tool".to_string()],
            max_payload_bytes: 0,
        };
        group.bench_function("check_tool_denied", |b| {
            b.iter_batched(
                || SandboxEnforcer::new(sandbox.clone()),
                |e| e.check("any", "forbidden_tool", 0).unwrap_err(),
                BatchSize::SmallInput,
            );
        });
    }

    // Backend not allowed — returns Err on second check (backend allowlist)
    {
        let sandbox = SessionSandbox {
            max_calls: 0,
            max_duration: Duration::ZERO,
            allowed_backends: Some(vec!["allowed".to_string()]),
            denied_tools: vec![],
            max_payload_bytes: 0,
        };
        group.bench_function("check_backend_denied", |b| {
            b.iter_batched(
                || SandboxEnforcer::new(sandbox.clone()),
                |e| e.check("disallowed", "any_tool", 0).unwrap_err(),
                BatchSize::SmallInput,
            );
        });
    }

    // Payload too large
    {
        let sandbox = SessionSandbox {
            max_calls: 0,
            max_duration: Duration::ZERO,
            allowed_backends: None,
            denied_tools: vec![],
            max_payload_bytes: 1024,
        };
        group.bench_function("check_payload_too_large", |b| {
            b.iter_batched(
                || SandboxEnforcer::new(sandbox.clone()),
                |e| e.check("any", "any_tool", 2048).unwrap_err(),
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// ── criterion wiring ──────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_tool_registry,
    bench_simhash,
    bench_cache_key,
    bench_mcp_frame,
    bench_session_sandbox,
);
criterion_main!(benches);
