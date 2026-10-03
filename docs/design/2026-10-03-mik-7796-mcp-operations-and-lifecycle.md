# MIK-7796: MCP operation requirements, executor lifecycle, pyghidra

Status: for review. Scope: `service: mcp` capabilities (src/capability/executor/mcp.rs, definition/process.rs).

## 1. Operation-dependent required parameters

Problem. One input schema serves several operations (`pact_contracts.operation`, `openpencil_design.operation`,
`pyghidra_reverse.operation`). The schema can only say what is required for every call, so `get_contract`
without `component` passes validation, the argument template drops the unresolved `component_id`, and the child
rejects the call. The capability schemas may not compose subschemas (`anyOf`, `if`; test
`schema_2020_12_validity`, bound U9 unresolved), and the input validator reads only `required`, `enum`, bounds
and `pattern`.

Design. The requirement moves out of the schema into the operation's mapping, where the executor already
selects by operation:

```yaml
tool_selector:
  param: operation
  tools:
    get_contract:
      tool: pact_contract
      requires: [component]        # new
      arguments: { component_id: '{component}', project_dir: '{project_dir}' }
```

- `ToolCall.requires: Vec<String>` (default empty). `execute_mcp` checks it in `select()`, before a child is
  acquired: a name that is missing or null in the caller's parameters gives JSON-RPC invalid-params
  `operation 'get_contract' needs parameter 'component'`. No child starts, so no process is spent on a bad call.
- Load-time validation (`cap validate` and the loader): every `requires` name must be a declared input property,
  else the file fails with a named error (a typo cannot silently weaken the check).
- The tool schema published to clients stays flat. The operation `description` lines carry the requirement in
  prose (each file already lists operations); no schema composition is introduced.
- Out of scope: REST and CLI. CLI templates already refuse a missing placeholder; REST has `required`.

Rejected: `if/then` in the validator (needs the U9 composition bound first, and publishes composed schemas to
clients); making every unresolved placeholder an error (optional arguments rely on being dropped).

Tests (red first): missing required parameter refused before any child starts (assert child count 0); present
parameter proceeds; `requires` naming an undeclared property fails load; shipped catalogue: every `requires`
resolves.

## 2. Lifecycle fixes (one failing test each, written before the fix)

| ID | Defect | Fix | Failing test |
|----|--------|-----|--------------|
| L1 | A call that cloned its definition before an unload starts a child after it (and runs a stale or quarantined definition) | Revocable generation: the executor keeps a per-capability generation, bumped on unload, reload and quarantine. The backend reads it when it clones the definition and carries it on the execution context; `acquire` refuses a call whose generation is not current, before any child starts or tool is invoked. A call already past `acquire` is stopped by the forced eviction on unload | stale call after unload never starts a child and never reaches the tool |
| L2 | `discard` after a timeout removes whatever child now sits under the key | Each child has a generation; `discard` removes only the matching one | timed-out call must not remove a replacement child |
| L3 | A changed `provider.timeout` keeps the old child | Child records the timeout; a different one restarts it | acquire with a new timeout returns a new child |
| L4 | `last_used` set at acquire only, so a long call counts as idle | Set `last_used` when the lease ends | long call, then sweep: child stays |
| L5 | Stdio reader failure leaves pending calls waiting for their timeout | Drop all pending senders when the reader ends | pending call errors at once after an oversized frame |
| L6 | API-key callers without a verified identity share the operator child on a single-user gateway | Principal includes the authenticated key id when present | two key ids get two children |

L6 needs the key id on the execution context; if the context lacks it, the dispatch path adds it (named field,
no behaviour change for other capabilities).

## 3. pyghidra mapping (decision D4: slow call runs as a task, with a bounded wait inside)

`import_binary` is a background job in pyghidra-mcp; analysis finishes later. The capability is reached through
`gateway_invoke`, which is already task-dispatchable, so a caller runs the slow operation as a task. Inside the
call the executor needs a bounded wait:

- `ToolCall.wait: Option<WaitStep>` with `{ tool, arguments, until, interval_ms (200..=5000, default 1000),
  max_wait_s }`, where `until` is `{ array, match, field, equals }`: the poll result's `array` must hold an
  element whose `match` fields equal the given templates and whose `field` equals `equals`. For pyghidra:
  `list_project_binaries`, `array: programs`, `match: { file_path: "{binary_path}" }`, `field:
  analysis_complete`, `equals: true`, so "this binary is analysed" is expressible and the matching program name
  is bound for later operations. A poll that returns a tool error or no match counts as not ready (the server
  answers an absent or unfinished binary with an error); it never aborts the wait.
- Deadlines. `max_wait_s` must be at most the provider timeout minus 10 s (load-time check). Exhausting
  `max_wait_s` returns `BackendTimeout("analysis not finished within N s; call again to keep waiting")` and does
  NOT discard the child: the server is busy, not wedged, and its analysis continues. Only the outer call
  deadline (a server that stops answering) discards the child. The pyghidra provider timeout is 300 s.
- The wait holds the lease (`InFlight`) for its whole duration and is inside the same `tokio::time::timeout` as
  the call, so no path is unbounded and none outlives the lease.
- Operations (read-only): `import` (`import_binary`, wait on `list_project_binary_metadata` for the binary),
  `list_binaries`, `decompile` (`decompile_function`), `xrefs` (`list_xrefs`), `search_symbols`
  (`search_symbols_by_name`), `search_strings`, `imports`, `exports`, `callgraph` (`gen_callgraph`),
  `metadata`. Mutating tools (rename, set comment/type/prototype, delete) are not exposed. `import` changes the
  project, so the capability is `read_only: false`, `destructive: false`, and both response caches are off
  (`cache.strategy: none`): imports change state and child eviction discards it. `binary_path` carries `path_root: uploads` (the root documented for analysis input; the frozen 7782
  confinement of that parameter is unchanged). `env` allowlists `GHIDRA_INSTALL_DIR` and `JAVA_HOME` so the
  isolated child can find Ghidra.
- Verification: tool names and argument names are checked against the server's `tools/list` snapshot in a test
  (a mapped tool that the snapshot lacks fails it). A real Ghidra is not available in CI; this is stated in the
  PR.
- When mapped, `pyghidra_reverse` leaves the held list and the public count (item 2 of the ruling) rises by one.

## 4. Review questions

1. Is `requires` on the mapping the right place, versus a schema extension keyword (`x-requires`)?
2. Is reconcile-after-call enough for L1, or must `acquire` take an unload epoch?
3. Does the bounded `wait` leave any path for an unbounded loop or a held lease?
