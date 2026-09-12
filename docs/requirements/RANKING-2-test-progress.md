# MIK-3274.RANKING.2 — test-closure progress

## Routes (confirmed by reading the dispatch table)
`src/gateway/meta_mcp/mod.rs:1739` `gateway_search` -> `code_mode_search`
`src/gateway/meta_mcp/mod.rs:1746` `gateway_search_tools` -> `search_tools`
Both live in `src/gateway/meta_mcp/search.rs`. No third public discovery route
(`rg -n "backend_allowed|\.rank\(" src/`: only these two plus `spec_preview.rs`,
which is a feature-gated preview surface, not a discovery route).

## Fixture plan
- denied backend `gmail` / `send_email`, usage poisoned high -> would win outright
- allowed backend `mailroom`, tools in fixed Vec order:
  1. `email_digest_status` (weak relevance, poisoned global usage)
  2. `send_email` (strong relevance, zero usage)
- query "send email", limit 1

## Assertion map
- authorization before disclosure: allow-all profile ranks `gmail:send_email`
  first; restricted profile omits it entirely at a limit wide enough to hold it.
- ranking before truncation: limit 1 keeps `mailroom:send_email`, not the
  first-collected `email_digest_status`; `total_available` > `total`.
- feedback cannot promote: poisoned usage on the weak tool leaves it below.

## Status
- [ ] fixture written
- [ ] both routes covered
- [ ] gates green

## Outcome

Four tests in `src/gateway/meta_mcp/search_disclosure_e2e.rs`, covering both
public discovery routes:

| Test | Line | Route | Clause covered |
|---|---|---|---|
| `mik_gw_ranking2_code_mode_filters_forbidden_before_disclosure` | 414 | `gateway_search` | authorization precedes disclosure |
| `mik_gw_ranking2_code_mode_ranks_before_truncating` | 448 | `gateway_search` | ranking precedes truncation; poisoned feedback loses |
| `mik_gw_ranking2_search_tools_filters_forbidden_before_disclosure` | 494 | `gateway_search_tools` | authorization precedes disclosure |
| `mik_gw_ranking2_search_tools_ranks_before_truncating` | 521 | `gateway_search_tools` | ranking precedes truncation; poisoned feedback loses |

Measured scores for the fixture (query `send email`, 4096 recorded uses on the
two poisoned entries):

| Candidate | Relevance | Usage | Score |
|---|---|---|---|
| `gmail:send_email` (forbidden) | 15.0 | 4096 | 42.84 |
| `mailroom:send_email` (allowed, relevant) | 15.0 | 0 | 15.00 |
| `mailroom:email_digest_status` (allowed, weak) | 5.0 | 4096 | 14.28 |

Pre-ranking collection order is measured, not assumed: the glob query path
skips the ranker and returns `email_digest_status` first, so a truncate-first
implementation would return the weak tool at `limit: 1`.

## Known bound on the feedback clause

The forbidden-tool half of the clause is absolute: a denied backend never
reaches the ranker, so no usage count can promote it.

The weak-tool half is not absolute. The score is
`relevance * (1 + log2(uses + 1) * 0.15)`, so a lower-relevance candidate
overtakes a higher-relevance one once its usage factor closes the ratio. For
this fixture (5.0 against 15.0) the crossover is about 10 321 recorded uses.
The fixture is pinned at 4096, comfortably below it. Treating "irrelevant"
as "scores zero" keeps the guarantee absolute; treating it as "scores lower"
makes it a bound, not an invariant.

## Uncovered

`exclusion_for` (`src/ranking/mod.rs:668`) is still untested. It gates on
`RankingSignals` fields (safety, risk, grant, permission_fit, policy_fit)
rather than on the routing profile, so it is a separate mechanism from the
`backend_allowed` filter these tests cover, and driving it needs signals
injected into the match JSON rather than a profile.
