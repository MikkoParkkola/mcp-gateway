# Adaptive Ranking

AdaptiveRanking is the deterministic tool-ranking layer behind
`gateway_search_tools` and Code Mode `gateway_search`.

## What It Optimizes

The ranker keeps relevance as the primary signal, then safely adjusts ranking
with coarse metadata:

- Safety and risk markers.
- Grant and authorization status.
- Runtime health.
- Trust score.
- Cost tier or cost score.
- Latency score.
- Freshness score.
- Local usage feedback.

Unsafe, unauthorized, unhealthy, and very low-trust tools are suppressed before
relevance scoring can promote them. Included tools carry a `ranking` payload
with deterministic reasons and numeric signals so users can inspect why a tool
was included or downgraded.

## Privacy Boundary

Ranking explanations use static reason labels such as `intent_match`,
`cost_downgraded`, `latency_downgraded`, `trust_ok`, and
`local_feedback_boost`. They do not echo query text or tool arguments.

## Licensing Boundary

| Capability | Free/core | Enterprise license category |
|------------|-----------|-----------------------------|
| Local deterministic ranking | Included | Included |
| Safety, grant, trust, health, cost, latency, freshness signals | Included | Included |
| Per-result explanations | Included | Included |
| Local usage feedback | Included | Included |
| Organization policy weights | Not included | Included |
| Fleet telemetry, evaluation dashboards, A/B tests | Not included | Included |
| Governed feedback promotion and audit export | Not included | Included |

## Current Scope

This slice upgrades the core ranker and search-result JSON conversion. Follow-up
work should wire organization policy weights, fleet telemetry, controlled
feedback promotion, and offline evaluation dashboards.
