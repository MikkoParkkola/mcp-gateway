# Long-running calls: tasks, progress and cancellation

A tool call that takes minutes should not hold a request open the whole time. With tasks, the
gateway answers a call at once with a task id, runs the call in the background, and keeps the
result until you fetch it, even if the client disconnects in the meantime.

Tasks are part of MCP revision 2026-07-28, which the gateway serves by default
(`server.modern_protocol`). A client on an older revision gets JSON-RPC `-32601` for the task
methods, and its calls run synchronously as before ([MCP compatibility](PROTOCOL_COMPATIBILITY.md)).

## Start a task

Send an ordinary 2026-07-28 `tools/call` to `POST /mcp` (with the
`MCP-Protocol-Version: 2026-07-28` header) and add three things:

- a `task` member in `params` (`{}` takes the defaults);
- the tasks extension, `io.modelcontextprotocol/tasks`, in the client capabilities you declare;
- an idempotency key, `io.mcp-gateway/idempotency-key`, in `params._meta`. A retry with the same
  key returns the same task instead of running the call twice.

```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "tools/call",
  "params": {
    "name": "gateway_invoke",
    "arguments": { "server": "reports", "tool": "build_report", "arguments": {} },
    "task": {},
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientCapabilities": {
        "extensions": { "io.modelcontextprotocol/tasks": {} }
      },
      "io.mcp-gateway/idempotency-key": "build-report-2026-10-06"
    }
  }
}
```

The answer has `resultType: "task"` and a `taskId`. The call is already running.

A call becomes a task only when it targets `gateway_invoke`, `gateway_execute`,
`gateway_run_playbook` or a surfaced backend tool. Any other tool runs synchronously and
ignores `task`. The gateway refuses to create a task when:

| Condition | Answer |
|---|---|
| The tasks extension is not declared | An error whose `data.requiredCapabilities` names the extension |
| Auth is on and the caller presented no credential, for example on a public `/mcp` | `-32602` "no such task", the same answer as for a task that does not exist |
| No idempotency key | `-32602` "task creation requires an idempotency key" |
| The call needs a confirmation and the client did not declare `elicitation` | `-32021` |

## Follow a task

Every follow-up request carries the same `_meta` as the call that created the task: the
2026-07-28 protocol version and the tasks extension in the client capabilities. Without the
extension, the gateway refuses the request.

```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "method": "tasks/get",
  "params": {
    "taskId": "task-…",
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientCapabilities": {
        "extensions": { "io.modelcontextprotocol/tasks": {} }
      }
    }
  }
}
```

| Method | Params | What it does |
|---|---|---|
| `tasks/get` | `{ "taskId": "…" }` | Returns the task: its status, and its result once it has finished |
| `tasks/update` | `{ "taskId": "…", "inputResponses": { … } }` | Answers a task that is waiting for input |
| `tasks/cancel` | `{ "taskId": "…" }` | Cancels the task |
| `subscriptions/listen` | names the task ids under `taskIds` | Streams `notifications/tasks` as tasks change, so you need not poll |

A task's status is one of `working`, `input_required`, `completed`, `failed` or `cancelled`.
Each new task carries a suggested poll interval, by default one second.

**Input mid-task.** A task that needs an answer, such as a confirmation, stops at
`input_required` and lists what it is asking. Send the answers with `tasks/update`, keyed as
asked, and the same call resumes. It does not run a second time. A key that matches no open
question is refused.

## Who can see a task

- With auth on, a task is visible only to the caller that created it. Any other caller gets the
  same answer as for a task that does not exist. A caller without a credential cannot create,
  read or cancel tasks at all.
- With auth off, every caller is the same caller. Anyone who can reach the gateway and knows a
  task id can read or cancel that task.
- The result is checked against current policy each time it is read. If a grant was revoked, a
  backend was killed or a tool was withheld after the task finished, the read returns the
  policy error and no result.
- The per-backend route `POST /mcp/{name}` answers every `tasks/*` method with `-32601`. Create
  and follow tasks through `POST /mcp`.

## Storage and limits

Tasks are kept on disk under `tasks.store_dir`. One gateway holds the store at a time. Back it up
only while every gateway that writes to it is stopped.

| Setting | Default | Meaning |
|---|---|---|
| `tasks.store_dir` | `~/.mcp-gateway/tasks` | Where tasks are stored |
| `tasks.default_ttl_ms` | `86400000` (24 hours) | How long a task is kept; `0` keeps it indefinitely |
| `tasks.poll_interval_ms` | `1000` | Suggested poll interval; `0` omits it |
| `tasks.max_records` | `256` | Live tasks in the whole store |
| `tasks.max_per_principal` | `32` | Live tasks per caller |
| `tasks.max_workers` | `16` | Tasks running at once |
| `tasks.max_record_bytes` | `524288` (512 KiB) | Largest stored task |
| `tasks.expiry_interval` | `60s` | How often expired tasks are swept |

At shutdown, a task that is still running when `server.shutdown_timeout` runs out is cancelled.
To let long tasks finish, raise that timeout.

**stdio.** A gateway started with `mcp-gateway serve --stdio` keeps tasks for the client that
launched it in `<tasks.store_dir>/stdio`, apart from the HTTP store. No HTTP caller can reach
them. If a second stdio gateway starts on the same config, it finds the store taken and runs
calls synchronously.

## Progress and cancellation without a task

A call that is not a task can still report progress and be cancelled:

- **Progress.** Put a `progressToken` in the call's `_meta`. A stdio or WebSocket backend's
  `notifications/progress` for that call reaches you while the call runs, carrying your own
  token. Over HTTP, the request must accept `text/event-stream` for progress to arrive before
  the result.
- **Cancel over stdio.** Send `notifications/cancelled` with the request id. The gateway stops
  handling the call at once and never answers it. A backend that has already received the call
  may still finish its own work. If a keyed call is cancelled after it started, a retry with the
  same key is refused rather than run a second time.
