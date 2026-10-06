# Code Mode

Code Mode shrinks what your AI client sees to two tools: `gateway_search` and `gateway_execute`. Every backend tool and REST capability is still reachable, through those two. Use it when you want the smallest possible tool list in the prompt, whatever the number of backends.

It is off by default. Without it the client gets the normal meta-tool set (9 to 17 tools, 11 in the default HTTP deployment; see [Meta-tools](../README.md#meta-tools)).

## Turn it on

Add this to `gateway.yaml` and restart the gateway:

```yaml
code_mode:
  enabled: true
```

The config file must be readable only by you (`chmod 600 gateway.yaml`). The gateway refuses to load one that other users can read.

## What the client sees

`tools/list` returns exactly two tools:

| Tool | Does |
|------|------|
| `gateway_search` | Finds tools by keyword, multi-word query or glob (`file_*`). Returns `server:tool` names. |
| `gateway_execute` | Runs one tool by its `server:tool` name, or a `chain` of calls in order. |

Tools listed under `meta_mcp.surfaced_tools` are not added in this mode, so the count stays at two.

Existing clients that call `gateway_invoke` by name keep working. It is not listed, but it still answers, and it passes the same checks as `gateway_execute`: a tool your policy denies is refused the same way on both paths.

## A session

Search first:

```json
{"name": "gateway_search", "arguments": {"query": "tide harbour"}}
```

```json
{"matches": [{"tool": "tidebook:tide_table", "description": "Look up the tide table for a harbour.", "score": 14.0}],
 "query": "tide harbour", "total": 1, "total_available": 1}
```

`gateway_search` answers at detail level L0 by default: name, one-line purpose, score. Pass `"detail": "l1"` for the signature and required parameters, `"detail": "l2"` for the full input schema, and `"explain": true` for ranking diagnostics. `limit` defaults to 10 and is capped at 25.

Then execute, using the name exactly as search returned it:

```json
{"name": "gateway_execute", "arguments": {"tool": "tidebook:tide_table", "arguments": {"harbour": "Oslo"}}}
```

The answer is the backend tool's own result, plus a `trace_id` you can find in the gateway log.

To run several calls in order, pass `chain` instead of `tool`:

```json
{"name": "gateway_execute", "arguments": {"chain": [
  {"tool": "tidebook:tide_table", "arguments": {"harbour": "Oslo"}},
  {"tool": "tidebook:tide_table", "arguments": {"harbour": "Bergen"}}
]}}
```

The answer lists each step's result in order:

```json
{"steps": 2, "results": [
  {"step": 0, "tool": "tidebook:tide_table", "result": {"content": [{"type": "text", "text": "..."}]}},
  {"step": 1, "tool": "tidebook:tide_table", "result": {"content": [{"type": "text", "text": "..."}]}}
]}
```

Backend tools show up in search once the gateway has started their servers and fetched their tool lists. That takes a moment after startup, so a search in the first seconds can come back empty for a backend that is still starting.

## Errors

A failed call comes back as a normal tool result whose payload has `"isError": true` and a message saying what went wrong. Read the payload, not only the outer result.

| You did | You get |
|---------|---------|
| Named a tool the backend does not have (`tidebook:no_such_tool`) | `isError: true`, "the backend does not list a tool named `no_such_tool`" |
| Named a server that is not configured (`nosuch:tool`) | `isError: true`, "Backend not found: nosuch", `recovery.error_code: TOOL_NOT_FOUND` |
| Passed a bare tool name (`tide_table`) | JSON-RPC error `-32602`: the reference is missing its server prefix; use `server:tool_name` from `gateway_search` |
| Called a backend whose server will not start | `isError: true`, a transport error such as "stdio backend ... exited before initialize (exit status: 3): missing_module, stderr matched \"Cannot find module\"", `recovery.error_code: BACKEND_ERROR`, `recovery.retry: true` |
| Called a tool `security.tool_policy` denies | HTTP 403 with JSON-RPC error `-32600`: "Tool '...' on server '...' is blocked by security policy" |

A backend that fails does not take the gateway down: other backends keep answering.

## Tested

`tests/e2e_code_mode_journey.rs` runs this page against the built binary in CI: the two-tool listing, search, execute (with its `trace_id`), a two-step chain, every error in the table with the fields shown, and `gateway_invoke` by name, including the policy refusal it shares with `gateway_execute`.
