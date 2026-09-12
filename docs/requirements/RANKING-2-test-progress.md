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
