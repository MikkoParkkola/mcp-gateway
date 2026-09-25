<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# NFR.WORKLOAD.1: build the invoke log notification only when it will be delivered

Status: reviewed (grok SHIP, kimi SHIP); suggestions folded in.

## Problem

Every Meta-MCP `tools/call` reaches `emit_log` in `src/gateway/meta_mcp/invoke.rs`
(`:1922`, the "tool invoked" audit line; `:1660`, the OAuth-isolation refusal).
Each call builds a `json!` payload at the call site, then `emit_log`
(`src/transport/notification_sink.rs:247`) builds a `JsonRpcNotification`
(two `String`s plus a second `json!` holding a clone of the payload) and hands it to
`publish`. There, `passes_level_filter` drops it unless the request declared a
level at or below the raised one.

The request-level slot is seeded `None`, which means silence (`notification_sink.rs:46-51`),
so a caller that never declares a level (the NFR.WORKLOAD.1 harness, and most
clients) pays for building and destroying the notification on every call.

Measured on bench-host (instructions per `tools/call`, gateway only, six interleaved
rounds, median): tip with #741 704.6K; the same build with both `emit_log` call
sites compiled out 680.4K. Paired per round the saving was positive in 4 of 6
rounds (median ~26K). About one point of p50 latency, by the ~25K-per-point scale in
MIK-7536.

## Proposal

`emit_log` takes the payload lazily and checks deliverability before building
anything:

```rust
pub(crate) fn emit_log(level: LoggingLevel, logger: &str, data: impl FnOnce() -> Value)
```

It returns before calling `data` unless both hold:
1. the request declared a level (`LEVEL` is `Ok(Some(declared))`);
2. `level >= declared`.

No separate sink check: `scope` installs `LEVEL` around `SINK` (`notification_sink.rs:72-75`), and `publish` is a no-op without a sink anyway (kimi review).

Otherwise it builds and publishes exactly as today. `publish` still runs
`passes_level_filter`, so the delivery rule has one owner and the early return
can only drop what `publish` would drop. It never admits anything `publish`
would refuse.

The two call sites pass `|| json!({...})` instead of `&json!({...})`. The
`tracing::info!`/`warn!` lines beside them are untouched: operator logging is a
separate channel, and `RUST_LOG` already governs it.

## Why behaviour is unchanged

- Same three conditions `publish` + `passes_level_filter` apply, evaluated
  earlier. A notification that passes the early check still goes through the
  full filter.
- The payload is a pure function of values already computed at the call site
  (`agent_label`, `declared_label`, `server`, `tool`, `trace_id`), so
  deferring it has no side effect to reorder.

## Tests

Existing, must stay green: `src/gateway/meta_mcp/outbound_log_tests.rs`
rows 1 and 2, unparseable level, and above-level filtering.

New. These can't run red on today's code, because they need the lazy signature; the four existing rows above are the behavioural regression net (kimi review).
- L1: outside any sink scope, the payload closure is never called.
- L2: in a scope with no declared level, the closure is never called.
- L3: declared `error`, raised `info`: the closure is never called.
- L4: declared `info`, raised `info`: the closure is called once, and one
  notification carrying its payload is published.
- L5: declared `debug`, raised `info`: called once and published, which pins
  the comparison as `>=`, not equality (grok review).

After the change lands, instructions per call are re-counted on the built change,
not the compile-out estimate (both reviews).

## Out of scope

- The other 4.0-only per-call costs (prompt-cache key hash, protocol telemetry,
  dispatch accounting). Each is a few K instructions; they're only worth
  taking up if the graded run at the #741 tip still fails.
