# PR #473 unreviewed-slice review — shard: `src/gateway/` excluding `meta_mcp/`

Range `c3626cf8..60b138bb10a869703254eae2fe500f055d96f8d7`, pinned SHAs, not the worktree.

## Payload

    git diff c3626cf8 60b138bb -- src/gateway/ ':(exclude)src/gateway/meta_mcp/'

| field | value |
|---|---|
| sha256 | `616d639d3bf000e49a8385d323cc041c257492a2f82b4202445b2dc9a8de5192` |
| bytes | 309,292 |
| files | 26 |
| insertions | 5,326 (deletions 291) |

309 KB exceeds the ~150 KB single-payload ceiling in the brief, so the payload was
split three ways along module lines and each part reviewed by both vendors. The
three parts partition the whole: 7 + 7 + 12 = 26 files, 90,654 + 90,974 + 127,664
= 309,292 bytes, matching the combined payload exactly.

| part | sha256 | bytes | files |
|---|---|---|---|
| A — `router/` | `90dd712f5a5bcddd1662c09fb3d6b9659308f2a8e1f89de290879f2712ad6cbb` | 90,654 | 7 |
| B — `server/`, `session_lifecycle`, `subscription_registry`, `streaming`, `recovery`, `mod` | `9f6054cd41790ffcabc5fb2bf361b8c3421851276c27ebe63f83959183be9c4e` | 90,974 | 7 |
| C — `input_bridge`, `proxy`, `destructive_confirmation`, `meta_mcp_helpers*`, `meta_mcp_tool_defs*`, `webhooks/`, `search_disclosure`, `ui/` | `f5b8db9260c9921c3ae7d75fac48807dc57d5bdb85ec7c4129c5f9322fb4678e` | 127,664 | 12 |

## Ledger rows

PENDING

## Findings

PENDING

## Coverage limits

PENDING
