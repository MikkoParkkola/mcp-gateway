# ADR-017: Windowed counters for the web UI's history

- **Status**: Proposed, 2026-10-25
- **Ticket**: MIK-8839 (ADR.1); unblocks U1 (MIK-8854), and through it U2, U3, U13 and every chart in the new UI
- **Base**: `docs/ranking-1-release-line` at `d13b042cb`

## Context

The new UI (MIK-8791, frames in `~/github/mcp-gateway-ux-design/png/r6/`) draws history everywhere: calls per 30 minutes against the same hours a day earlier, "↗ 9% vs the hour before", 30 days of spend per key, a 7-day uptime strip, restart marks. None of it can be computed today.

| # | Fact | Where |
|---|---|---|
| F1 | Usage counters are cumulative, in memory, and reset on restart. | `src/stats.rs:15` (`UsageStats`) |
| F2 | The only windowed buckets are cost buckets: hourly, in memory, bounded so memory never grows with calls. | `src/cost_accounting/mod.rs:9`, `:214` (MIK-8000) |
| F3 | Today's spend is saved to `~/.mcp-gateway/costs.json`, periodically and on shutdown, and restored on the same day. | `src/cost_accounting/persistence.rs:6`, `:16-17`; `src/gateway/server/persistence.rs:110`, `:166`, `:284` |
| F4 | The per-tool and per-key day maps already cap their size and fold the rest into an overflow total. | `src/cost_accounting/persistence.rs` (`tool_overflow_usd`, MIK-8015) |
| F5 | The flow map at scale needs caller × server counts; 140 servers × callers × buckets multiplies. | api-gaps.md Risk 8 |

## Options

1. **A snapshot file beside `costs.json`** (`counters.json`), holding fixed rings of buckets, written by the same periodic saver and on shutdown. No new dependency; the pattern is already proven twice (F3, and the search ranker's `usage.json`, `src/gateway/server/build_meta.rs:133`).
2. **An embedded database** (SQLite or redb). Queries over arbitrary windows, but a new dependency on the trust path, a schema to migrate, and a second persistence pattern beside F3.
3. **Prometheus as the store.** The gateway exports, the UI queries an external Prometheus. The UI then depends on infrastructure most single-host operators do not run, and the gateway cannot draw its own history.

## Decision

Option 1.

- **Buckets.** Each series keeps 96 half-hour buckets (48 hours) and 30 daily buckets in a ring. Half-hour buckets answer the 30-minute charts with the same hours a day earlier, and add up to the hourly views ("last hour vs the hour before"); daily buckets answer the 30-day charts. Day boundaries follow ADR-026.
- **Series.** Calls, failures, firewall catches and cache hits, each globally, per server, per key and per tool; added latency. Spend stays in the cost tracker's existing hourly buckets (F2), and the cost saver writes those buckets too, not only today's totals, so the 30-day spend charts survive a restart like the call charts.
- **Cardinality cap.** Per dimension, at most 512 entries per window, and caller × server at most 2,048 pairs; the rest fold into one `other` series per dimension, as F4 does for cost. Names longer than 128 bytes are truncated with a hash suffix, so the cap bounds bytes as well as entries. The UI's "+N more" fold is the same idea client-side. The caps are constants, not settings.
- **Persistence.** `~/.mcp-gateway/counters.json`, written by the existing periodic saver and on shutdown, restored at start. A periodic save can be skipped while the previous write is still running, so a crash loses everything since the last successful save, which is usually one interval and can be more.
- **Restart.** A restart leaves a gap: buckets for the time the process was down stay empty, and the restart is a marker on every chart (frames 26s, 40, 41).
- **Before U1 ships.** Charts that need history are labelled "since restart", or hidden, never drawn from cumulative counters as if they were windowed.

## Consequences

- No new dependency; one more file in the data directory, bounded by the cap (an estimate of a few MB at the caps, to be measured in U1).
- Arbitrary windows are not queryable; a range the rings do not hold (say 90 days) needs a new decision.
- Rare callers and servers beyond the caps lose their own line and show inside `other`; totals stay exact.
- `UsageStats` (F1) keeps serving the existing `/ui/api/status` shape until the old page is retired.
