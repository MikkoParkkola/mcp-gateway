# Adaptive Ranking

AdaptiveRanking is the deterministic tool-ranking layer behind
`gateway_search_tools` and Code Mode `gateway_search`.

## What It Optimizes

The ranker keeps relevance as the primary signal, then safely adjusts ranking
with coarse metadata:

- Safety and risk markers.
- License and local policy fit.
- Grant and authorization status.
- Runtime health.
- Trust score.
- Cost tier or cost score.
- Latency score.
- Historical success rate.
- Freshness score.
- User and organization preference scores.
- Local usage feedback.

Unsafe, high-risk, policy-denied, unauthorized, unhealthy, and very low-trust
tools are suppressed before relevance scoring can promote them. Included tools
carry a `ranking` payload with deterministic reasons and numeric signals so
users can inspect why a tool was included or downgraded.

## Signal Schema

Every included result exposes the coarse `ranking.signals` object. Scores are
normalized to `0.0..=1.0` unless noted.

| Signal | Meaning | Default |
|--------|---------|---------|
| `relevance` | Text, keyword, synonym, and schema-field match strength | `0.0` |
| `safety` | Hard safety fit; `0.0` suppresses output | `1.0` |
| `risk` | Inverse risk fit; `1.0` is low risk, `0.0` suppresses output | `1.0` |
| `trust` | TrustCard/TrustLab or metadata trust score | `1.0` |
| `grant` | Backward-compatible grant/authorization fit | `1.0` |
| `policy_fit` | License and local policy fit; `0.0` suppresses output | `1.0` |
| `permission_fit` | Identity, scope, and permission fit | `1.0` |
| `runtime_health` | Backend/runtime health; `0.0` suppresses output | `1.0` |
| `cost_efficiency` | Cost fit, including cost tier aliases | `1.0` |
| `latency` | Latency fit, including latency-ms conversion | `1.0` |
| `success_rate` | Historical success or reliability rate | `1.0` |
| `freshness` | Metadata or TrustCard freshness | `1.0` |
| `user_preference` | Local user preference fit | `1.0` |
| `organization_preference` | Organization preference fit | `1.0` |
| `user_feedback` | Local usage feedback boost derived from server/tool counters only | `0.0` |
| `usage_count` | Local usage count for the server/tool pair; no query or payload text | `0` |

## Privacy Boundary

Ranking explanations use static reason labels such as `intent_match`,
`cost_downgraded`, `latency_downgraded`, `trust_ok`, and
`local_feedback_boost`. They do not echo query text or tool arguments.

Offline evaluation reports follow the same boundary. Fixture cases include
queries so the ranker can evaluate them, but the emitted report references only
case IDs, expected tool names, actual tool names, baseline tool names, aggregate
hit rates, filtered-candidate counts, and static improvement target labels.

## Offline Evaluation

`SearchRanker::evaluate_offline` accepts deterministic fixture cases and
compares adaptive ranking against a text-only baseline. The baseline uses the
same relevance scorer without safety, grant, health, trust, cost, latency,
freshness, or feedback signals. This makes the report useful for proving:

- no regression against current text relevance behavior;
- safety or trust lift when adaptive prefilters suppress risky exact matches;
- measurable next targets such as fixture-corpus size, top-1 hit rate,
  challenger-case coverage, and policy-prefilter coverage.

The initial fixture tests cover a literal relevance case, a semantic discovery
case, and an unsafe exact-match case where adaptive ranking correctly selects a
safe tool that the text-only baseline would not rank first.

Run the same evaluator from the CLI when you need reproducible evidence:

```bash
mcp-gateway ranking eval ranking-fixtures.json --format json
```

The input can be either a JSON array of cases or an object with a `cases`
array. Each case uses a stable `id`, the private `query` consumed during
evaluation, the `expected_top_tool`, and candidate objects with the same
`server`, `tool`, `description`, and signal fields returned by gateway search.
The emitted `ranking-eval.v1` report intentionally omits query text and
candidate payloads; it contains only aggregate rates, case IDs, expected and
actual top tools, baseline top tools, filtered/invalid counts, and static
improvement targets.

Use the CLI gate for local or CI evidence:

- `top1_hit_rate` should stay at or above the ticket target for the fixture set.
- `regressions_vs_baseline` should be zero unless the case is explicitly
  accepted as a safety-driven tradeoff.
- `improvements_over_baseline` and `filtered_candidates` prove safety/trust lift
  when risky exact matches are suppressed.

## Licensing Boundary

| Capability | Free/core | Enterprise license category |
|------------|-----------|-----------------------------|
| Local deterministic ranking | Included | Included |
| Safety, grant, trust, health, cost, latency, freshness signals | Included | Included |
| Per-result explanations | Included | Included |
| Local usage feedback | Included | Included |
| Local offline fixture evaluation and `ranking eval` CLI | Included | Included |
| Organization policy weights | Not included | Included |
| Fleet telemetry, evaluation dashboards, A/B tests | Not included | Included |
| Governed feedback promotion and audit export | Not included | Included |

## Current Scope

This slice upgrades the core ranker, search-result JSON conversion, and local
offline evaluation. Follow-up work should wire organization policy weights,
fleet telemetry, controlled feedback promotion, and enterprise evaluation
dashboards.
