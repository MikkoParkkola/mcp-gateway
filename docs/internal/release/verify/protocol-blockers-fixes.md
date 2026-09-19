# PR #473 — `src/protocol/` blocker fixes

Findings from `docs/release/verify/pr473-protocol.md`, one commit each.

Path note: the report cites B4 and B6 at `src/gateway/meta_mcp/param_headers.rs`.
That file does not exist. The payload was `git diff -- src/protocol/`, and the
code is at `src/protocol/param_headers.rs`. No ownership question arises.

| finding | verdict | commit |
|---|---|---|
