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

A ledger row's `material_sha256` is NOT the payload hash. `gpt-review`'s
`digest_material` hashes `printf '%s\0' "$*"` followed by the stdin file, so for a
stdin review with no scope arguments the digest covers one NUL byte plus the payload
— `material_bytes` is always payload+1. The binding hashes for the three parts are
therefore:

| part | payload sha256 (first 12) | ledger material_sha256 | material_bytes |
|---|---|---|---|
| A | `90dd712f5a5b` | `6a8e623bbfeb318789e1dbac1ab2370ecf4568ecde86806d6fd30e40bfa37fca` | 90,655 |
| B | `9f6054cd4179` | `cf9d01d995e705ce38159302c42bfed17c48f43d319dbf073bba57b5db691975` | 90,975 |
| C | `f5b8db9260c9` | `7c787ed95fa1699e0e6d34d81b393459ed58a0840c3cfb66c6de3c71ffff741e` | 127,665 |

Rows, by vendor and part:

PENDING

## Findings

PENDING

## Coverage limits

Stated plainly, because silent truncation reads as coverage.

- **The split separates new code from its call sites.** `subscription_registry.rs`
  (part B, 354 changed lines) is consumed from `router/handlers.rs` (part A);
  `input_bridge.rs` and `destructive_confirmation.rs` (part C) are likewise reached
  from part A. No single reviewer held both ends of those contracts, so a mismatch
  between a new registry API and its caller is exactly the defect class this payload
  split is blind to. Findings that span the cut had to be judged during source
  verification rather than by a reviewer.
- **`src/gateway/meta_mcp/` is out of shard** and is reviewed separately. The
  `meta_mcp_helpers*.rs` and `meta_mcp_tool_defs*.rs` siblings that sit directly under
  `src/gateway/` ARE in this payload; only the directory is excluded.
- **The reviewers ran as a harness-tracked background task**, not in the task
  foreground the brief specifies. The brief's constraint targets `nohup`, which dies
  with its parent; the Bash tool caps a foreground call at 120s against the brief's
  own >=300000ms floor, so a foreground run could not have completed. The background
  task is tracked by the harness, survives, and each run's verdict was taken from the
  ledger row, not from the task's own exit reporting.
- **Only the diff was reviewed, not the built tree.** No build, no test run, no
  clippy pass was performed for this shard. Findings about missing dispatch or
  unbounded growth are source-level; runtime behaviour is unverified.
