# MIK-7782: executing `service: cli` and `service: mcp` capabilities

Status: draft for review (round 1). Operator ruling 2026-10-02 (chat): "build and fix, we need to deliver
our promise". Covers MIK-CAPEXEC.DESIGN.1, CLI.1, MCP.1, SEC.1, CAT.1, ATTACH.1, CLAIM.1.

## 1. Facts (base 60793344c)

1. `dispatch_protocol` (`src/capability/executor/mod.rs:443-481`) runs `rest`, `graphql`, `jsonrpc` only.
   `ProviderConfig::protocol_config` (`src/capability/definition/mod.rs:261-325`) maps any other `service`
   to REST with a warning; `RestConfig` has no `command`/`args`/`transport`/`env`, so serde drops them.
   25 shipped files use `service: cli` (19) or `service: mcp` (6); none has ever executed (v3.5.1 too).
2. Pinning (`src/capability/hash.rs:79-90`, `parser.rs:42-71`): a wrong pin fails closed at load and on
   hot reload (`backend.rs:616-634`, rug-pull unload). **A missing pin loads** with a DEBUG line.
   `tests/capability_pin_policy.rs:111-150` already requires a pin on every shipped `cli`/`mcp` file.
   A pin proves integrity of the file, not who wrote it: anyone who can write the directory can re-pin.
3. Capability calls run inside the same wrapper as backend calls (`gateway/meta_mcp/invoke.rs`): input
   firewall (`router/handlers.rs:1339`), kill switch and capability disable (`invoke/dispatch_guards.rs:112`),
   one audit record per call (`invoke/audit.rs`), caller identity resolution (`invoke.rs:1530`), error
   budget to auto-kill (`invoke.rs:2606`), output firewall (`response_security.rs:168`). All keyed on the
   capability name. The executor needs no second copy of these gates.
4. MCP client stack: `Backend::new(name, BackendConfig, ..)` (`src/backend/lifecycle.rs:121`),
   `Backend::request("tools/call", ..)` (`src/backend/ops.rs:124`). Stdio spawn is `Command::new` on a
   split command string, no shell (`src/transport/stdio.rs:161`), with `env_clear()` plus PATH/HOME/TMPDIR
   (and the Windows profile set) in `configure_child_environment` (`stdio.rs:42`), `kill_on_drop(true)`.
5. The only no-shell argv runner, `StdRuntimeCommandRunner::run` (`src/runtime/provider.rs:662`), is
   synchronous with no timeout. It resolves allowlisted env keys through the `LiveEnv` overlay.
6. No spawn path resolves Windows `.cmd`/`.bat` (`src/commands/doctor.rs:703`); npm installs `gws` as
   `gws.cmd` on Windows.
7. MIK-7775 (#2683) adds CAP-012, a warning for every provider key no field reads. It goes quiet for
   `command`, `args`, `transport`, `env` once the typed configs below read them.

## 2. Per-capability audit (each checked against the real tool, 2026-10-02)

| Capability | Real tool | State | Fix |
|---|---|---|---|
| 17 `gws_*` | `@googleworkspace/cli` 0.22.5 | 12 match after arg fixes; 5 wrong flags | see §2.1 |
| `trawl_extract` | `trawl` (Go/cobra, operator repo) | `args_template` is Liquid, never read | structured args, URL after `--`, SSRF check |
| `metacognition_verify` | `metacognition` 0.7.0 (clap) | positional text reads `@file`, `setup` runs a subcommand | text on **stdin** (`-`), never argv |
| `openpencil_design` | `openpencil-mcp` 0.15.1, 106 tools | 5 of 8 operations name no real tool | operation-to-tool map: `create_node`→`create_shape`, `export_png`→`export_image`, `set_auto_layout`→`set_layout`, `get_design_tokens`→`design_to_tokens`, `list_components`→`get_components` |
| `pact_contracts` | `pact-mcp` (pact-agents 1.2.0), 7 tools | names differ; every tool takes `project_dir`, which the capability lacks (the server would read its own cwd) | map `verify_contract`/`validate_gate`→`pact_validate`, `list_contracts`→`pact_contracts`, `get_contract`→`pact_contract{component_id}`, `check_budget`→`pact_budget`, `get_retrospective`→`pact_retrospective`, `resume_run`→`pact_resume` (starts a paid run: `read_only: false`); add `project_dir` (limited to a configured root, §6.2) |
| `pyghidra_reverse` | `pyghidra-mcp` 0.2.7 | tool and argument names differ; needs Ghidra + JDK | map `decompile`→`decompile_function`, `get_xrefs`→`list_xrefs`, `get_call_graph`→`gen_callgraph`, `search_symbols`→`search_symbols_by_name`, `disassemble`, `analyze_binary`→`import_binary`; test double in CI |
| `cloudflare_manage` | declared `npx @anthropic/cloudflare-mcp`: **package does not exist** | real `@cloudflare/mcp-server-cloudflare` 0.2.0 has zones, workers, R2; **no DNS, WAF or cache-purge tools** | 5 of 12 operations mappable; 7 need a decision (§9) |
| `cisco_scanner` | `cisco-ai-mcp-scanner` 4.8.5 | **ships no MCP server** (CLI `mcp-scanner` + REST API); no skill scanning | 1 of 5 mappable: `scan_mcp_server` as `service: cli` `mcp-scanner remote --server-url=<url> --raw` (URL egress-checked; the `stdio` subcommand runs a command and is never reachable); 4 need a decision (§9) |
| `desktop_event_bus` | `axterminator mcp serve` 0.10.2, 62 tools | **no event-bus tools**; subscriptions are a stream, not request/response | not executable; decision (§9) |

### 2.1 gws argument fixes

`calendar_insert`: `--calendar`, repeated `--attendee`. `docs_write`: `+write --document --text` (no
`--title`; `documentId` becomes required, `title` dropped). `drive_upload`: `drive +upload [--name]
[--parent] -- <file>`, no `--mime-type`. `gmail_reply`: no `--thread-id` (gws threads itself).
`chat_send`: no `--thread-key`. `gmail_send`: map the declared `cc`/`bcc`. Eight raw-API files build
`--params`/`--json` by pasting strings into JSON text; they move to structured JSON arguments (§3.2).
Each schema change is listed in UPGRADING and the changelog.

## 3. Config schemas

`providers.<name>.config` stays the YAML key. `protocol_config` gains two arms that deserialize the same
mapping into typed structs with `#[serde(deny_unknown_fields)]`; a bad key is a load error naming the
file. `ProtocolConfig::Cli(Box<CliConfig>)` and `ProtocolConfig::Mcp(Box<McpConfig>)` replace the
placeholder comment at `definition/mod.rs:624`. The REST catch-all for other unknown services stays.

### 3.1 `service: cli`

```yaml
providers:
  primary:
    service: cli
    timeout: 15                    # seconds (existing field); hard ceiling 300
    config:
      command: gws                 # bare name looked up on PATH, or an absolute path; never templated
      args:                        # one YAML item = exactly one argv element, never re-split
        - gmail
        - +send
        - "--to={to}"              # option value bound with '=': it cannot become a separate flag
        - "--subject={subject}"
        - { arg: "--cc={cc}", if: cc }      # emitted only when the caller supplied `cc`
        - { json: "--params=", value: { userId: me, q: "{query}", maxResults: "{maxResults}" } }
        - "--"                     # end of options
        - "{filePath}"             # placeholders standing alone are allowed only after "--"
      stdin: "{text}"              # optional; the route for free text into tools that parse @file
      env: [CLOUDFLARE_API_TOKEN]  # allowlist of variable NAMES, resolved via the LiveEnv overlay
      output: json                 # json (stdout must parse) | text (returned as {"text": ...})
      max_output_bytes: 1048576    # default 1 MiB, ceiling 8 MiB, stdout and stderr each
```

No configurable `cwd`: the child runs in a fresh empty directory under the gateway's private temp area,
removed after the call. No shipped capability needs another (add one when a capability does).

### 3.2 Substitution rules (typed, never textual)

- `{p}` names an input-schema property (CAP-006 extended to `args`, `stdin`, `json` leaves and MCP
  `arguments`). Values are the schema-validated arguments (`validate_arguments`, `backend.rs:464`)
  merged with `static_params`.
- A string element holds at most one placeholder. Absent parameter and no `if:` means a parameter
  error; the element is never emitted as an empty string.
- `json:` walks `value`; a leaf that is exactly `"{p}"` becomes p's JSON value with its type kept, a leaf
  whose p is absent is dropped from its object, and the tree is serialized with `serde_json`. A value can
  never close a string or add a key.
- String elements take strings as-is and numbers/bools as JSON text; arrays/objects are refused there.
- Refused before spawn: any NUL; a value starting with `-` in a standalone element before `--` (cannot
  occur by construction: CAP check refuses such a config); line breaks in an `--x=` value unless the
  property declares `format: multiline` (gws `--body`, `--text`).
- No element, parameter or `command` ever reaches a shell.

### 3.3 `service: mcp`

```yaml
providers:
  primary:
    service: mcp
    timeout: 30
    config:
      command: openpencil-mcp      # stdio: static, pinned, never templated
      args: []                     # static strings only
      env: []                      # allowlisted names, as for cli
      # instead of command/args:  url: https://host/mcp   (streamable HTTP, egress-checked)
      tool_selector:
        param: operation           # input property that picks the tool
        tools:
          create_node: { tool: create_shape, arguments: { type: "{node_type}" } }
          query_nodes: { tool: query_nodes,  arguments: { selector: "{query}" } }
      # single-tool capability instead:  tool: pact_status  +  arguments: {...}
```

An operation value missing from `tools` fails closed, as `path_selector` does. `arguments` follows the
`json:` leaf rules. The existing `transport: stdio` key is accepted as a redundant literal.

## 4. CLI execution

New `src/capability/executor/cli.rs` (`CliExecutor`, a `ProtocolExecutor` like `rest.rs`):

1. Gate (§6.1), then build argv as a pure function `build_cli_invocation(&CliConfig, &Value) ->
   Result<CliInvocation>`; tests call it directly.
2. Resolve `command` once per call: absolute path as given; a bare name searched on the child's PATH.
   On Windows, PATH x PATHEXT (`.exe`, `.cmd`, `.bat`); a `.cmd`/`.bat` target runs through std's
   batch-argument escaping (Rust >= 1.77.2, CVE-2024-24576), which refuses arguments it cannot escape
   safely; that refusal maps to a parameter error. A name containing a separator but not absolute is
   refused.
3. `tokio::process::Command`, `kill_on_drop(true)`, stdin piped (or null), stdout/stderr piped.
   Environment: `configure_child_environment` (`stdio.rs:42`, made `pub(crate)`) baseline, then only the
   `env` allowlist, resolved through `LiveEnv` like `StdRuntimeCommandRunner` (`runtime/provider.rs:662`).
   The child gets its own process group (`process_group(0)`); timeout, cap overflow and drop kill the
   whole group with `rustix::process::kill_process_group` (safe API; `rustix` is already a direct
   dependency with `process`). This matters: gws's npm entry `run.js` is a node wrapper that
   `spawnSync`s the native gws binary, so killing node alone would orphan it.
   Windows: the same needs a Job object (`KILL_ON_JOB_CLOSE`), i.e. `unsafe` FFI in a module like
   `src/win_acl.rs` (the existing `allow(unsafe_code)` precedent) plus the `Win32_System_JobObjects`
   feature of `windows-sys`. Decision D5 (§9); without it, Windows kills only the direct child.
4. Read stdout and stderr concurrently, each into a buffer capped at `max_output_bytes`; past the cap
   the child is killed and the call fails `output too large` (never truncated JSON passed on as data).
5. `tokio::time::timeout(provider.timeout)`; on expiry kill the group and fail `timed out after Ns`.
6. Exit mapping: 0 parses stdout per `output`; non-zero fails with `Error::Protocol` carrying the exit
   code and the last 2 KiB of stderr (after the same redaction the REST path applies to bodies); a
   signal death says so. gws prints a JSON error object on stdout on failure: when stdout parses as
   JSON with an `error` key, its `message` is used.
7. Concurrency: a per-capability semaphore (default 4) bounds simultaneous children.

Long-running calls: the existing task mode (`B3`) applies unchanged because the executor is reached
from the same dispatch; nothing new.

## 5. MCP execution

New `src/capability/executor/mcp.rs` (`McpExecutor`). No new MCP client: each `service: mcp`
capability gets one `crate::backend::Backend`, built with `Backend::new` from a `BackendConfig`
(`TransportConfig::Stdio` with `join_command(command, args)`, or the HTTP transport for `url`), with
`env` filled from the allowlist and `timeout` from the provider.

- Ownership: a `McpCapabilityBackends` map (capability name to `Arc<Backend>`) owned by the
  `CapabilityExecutor`, created lazily on first call. It is NOT registered in `BackendRegistry` (it
  must not appear as a public server). Entries are stopped when the capability is unloaded or
  reloaded with a different definition hash, on gateway shutdown, and after 5 idle minutes by a
  `stop_idle()` call added to the existing idle sweep (`gateway/server/mod.rs:3665`).
- Call: resolve the tool and arguments (§3.3), `backend.request_with_headers("tools/call", {name,
  arguments}, .., identity_key)` with the caller identity key, so per-user partitioning matches
  backend calls. A JSON-RPC error or `isError: true` maps to `Error::Protocol` with the tool's text.
  `structuredContent` is returned when present, else the content array.
- The tool list is never exposed: the capability is the unit callers see and govern.

## 6. Security model

### 6.1 Execution gate (fail closed, checked on every call before any spawn or connect)

1. **Pinned and verified.** `CapabilityDefinition` gains `#[serde(skip)] integrity: Integrity`
   (`Verified` | `Unpinned`), set by `parse_capability_file` after the existing hash check. A `cli`/`mcp`
   definition that is `Unpinned` is refused with `capability '<n>' must be pinned (mcp-gateway cap pin)
   to run a local process`. A mismatched pin never loads (existing behaviour) and a pin changed on disk
   unloads the capability (existing rug-pull path) and stops its MCP child.
2. **Command allowlist.** Because a pin only proves integrity, config `capabilities.process_commands`
   lists the commands that may run. Default: the commands of the shipped catalogue (`gws`, `trawl`,
   `metacognition`, `mcp-scanner`, `openpencil-mcp`, `pact-mcp`, `pyghidra-mcp`, `npx` only with first
   arg `@cloudflare/mcp-server-cloudflare@<pinned version>`). Operators extend it for their own
   capabilities. A command not listed is refused at call time and reported by `cap validate`.
3. **Kill switch.** `capabilities.process_execution: enabled | disabled` (enum, default `enabled`), hot
   reloadable, refuses all `cli`/`mcp` calls when disabled. The per-capability kill switch and disable
   (`dispatch_guards.rs:112`) and the error-budget auto-kill already apply because the gate keys on the
   capability name. No new per-call flag.
4. Personal-account and identity validation (`execution_context.rs:369`) run as for REST.

### 6.2 Inputs and outputs

- Input firewall, audit record, caller identity and output firewall come from the shared invoke wrapper
  (fact 3). The executor adds to the audit record's detail: command name (never argv values),
  exit code, duration, bytes out.
- Egress parameters: `trawl_extract.url` and `cisco_scanner.target` are declared `format: uri` with
  `egress: true`; the executor runs `validate_capability_url_for_context` on them before spawn, the
  same check REST URLs get. Residual: the child resolves DNS itself, so rebinding after the check is not
  prevented (stated in docs).
- Local file parameters: `gws_drive_upload.filePath` reads any file the gateway user can read, and a
  remote caller could upload `~/.ssh/id_ed25519`. A path property declares `path_root: <name>`; the value
  must resolve (canonicalized, symlinks followed) inside `capabilities.files.<name>` from gateway config.
  Roots have no default: an unset root makes the capability refuse with a message naming the key.
  Used by `gws_drive_upload.filePath` (`uploads`), `pyghidra_reverse.binary_path` (`uploads`),
  `pact_contracts.project_dir` and `openpencil_design.file_path` (`projects`), and `downloads` for §7.

### 6.3 Secrets (CWE-532)

- Secrets reach a child only through the `env` allowlist, never argv (argv is visible in `ps`). The
  validator refuses `{env.X}` or `{access_token}` placeholders inside `args`/`stdin` (new check).
- Logs and errors carry the command name, never argv or stdin; stderr excerpts pass through the
  existing redaction. New structs holding env values get a manual `Debug`. `cwe532-leak-lint.py` runs
  unchanged in CI.
- `cloudflare_manage` today writes `{env.CLOUDFLARE_API_TOKEN}` into an env mapping; it becomes the
  allowlist entry `CLOUDFLARE_API_TOKEN`.

## 7. Attachments (ATTACH.1)

The embedded Python is deleted, never executed.

**`calendar_get_attachment`**: its Python only projects fields. It becomes the existing native
`transform: { project: [id, summary, attachments] }`; the output schema uses Google's field names
(`fileUrl`, `fileId`, `mimeType`, `iconLink`, `title`). The description is already accurate.

**`gmail_save_attachment`**: a new capability-level, declarative post-step, run after the REST response
and before the response transform:

```yaml
save_file:
  data: data             # response field holding the payload
  encoding: base64url    # base64url | base64 (padding optional for both)
  filename: "{filename}"
  max_bytes: 26214400    # 25 MiB, the Gmail attachment ceiling; hard ceiling 100 MiB
```

Result `{saved_path, size, filename}`, as the output schema already says; `data` is removed from the
response, so the bytes never reach the model or the output firewall as text.

- Directory: `capabilities.files.downloads` in gateway config, canonicalized at load. No default: when
  unset the capability refuses with a message naming the key. The `output_dir` parameter is removed
  (a caller-chosen directory is the traversal hole) and UPGRADING says so.
- Filename: one path component. Refused: empty, `.`, `..`, `/`, `\`, NUL, control characters, `:`
  (Windows streams), a trailing dot or space, Windows device names (`CON`, `NUL`, `COM1`..), longer
  than 255 bytes. No silent sanitizing: a refused name is an error the caller can correct.
- Write: `OpenOptions::create_new(true)` on `root.join(name)` (fails on any existing entry, including a
  symlink, so nothing is overwritten and no link is followed), mode 0600 on Unix. On a name clash try
  `name_1.ext`.. `name_99.ext`, then fail. A failed write removes the partial file.
- Size: refuse when the encoded length implies more than `max_bytes` before decoding; decode with the
  `base64` crate (already a dependency).
- Residual: a process that swaps `root` for a symlink between canonicalization and open is outside the
  model (the directory is operator-owned); stated in docs.

## 8. Test plan (all red on CI first, at their own assertions)

Doubles (stdlib Python, run as `python3`/`python` resolved per OS; the Windows CI image ships Python):
`tests/fixtures/cap_exec/argv_echo.py` prints `{"argv": [...], "stdin": "...", "env": {...}}` as JSON
and can be told (by a fixed argv marker the test controls, never by parameters) to exit N, sleep, spawn
a grandchild, or flood stdout. `tests/fixtures/cap_exec/fake_mcp.py` is a stdio MCP server that serves a
recorded `tools/list` snapshot and answers `tools/call` with the name and arguments it received.

| ID | Test | AC |
|---|---|---|
| T1 | `build_cli_invocation` golden argv for every shipped `cli` file, with typical parameters | CLI.1, CAT.1 |
| T2 | Hostile values through the real spawn path (argv_echo): `--attach=/etc/passwd`, `-a x`, `--draft`, `; rm -rf ~`, `$(id)`, backticks, `%PATH%`, `"`, newline, NUL, `@/etc/passwd`, `setup`, a 1 MiB string, non-ASCII. Assert: each value appears as exactly the bytes of ONE argv element (or stdin), argv length equals the golden length, or the call is refused with a parameter error; never an extra element | CLI.1 |
| T3 | JSON args: `"q": "x\", \"userId\": \"evil"` stays one string; numbers stay numbers; absent optional key dropped | CLI.1 |
| T4 | Env: child sees only the baseline plus allowlisted names; a gateway variable named `SECRET_X` absent | CLI.1, SEC |
| T5 | Timeout kills the child and its grandchild (Unix: the grandchild's pid is gone); stdout cap kills and errors; non-zero exit maps to an error with the code; gws-style JSON error message surfaces | CLI.1 |
| T6 | Windows (`cfg(windows)` job): a `gws.cmd` double on PATH resolves; hostile values T2 through the `.cmd` either arrive intact or are refused | CLI.1 |
| T7 | Unpinned `cli` and `mcp` definitions refused before spawn (argv_echo leaves a marker file; assert absent); tampered pin never loads; command outside `process_commands` refused; `process_execution: disabled` refuses | SEC.1 |
| T8 | No argv or stdin value appears in captured tracing output or the error text (a value containing a canary) | SEC |
| T9 | MCP: each shipped `mcp` file run against fake_mcp with its server's recorded snapshot; operation maps to the expected tool name and arguments; unknown operation refused; tool `isError` maps to an error; one child reused across calls and stopped on unload | MCP.1, CAT.1 |
| T10 | Snapshot conformance: every mapped tool name and argument name exists in the recorded `tools/list` of the pinned server version (`tests/fixtures/cap_exec/snapshots/<server>@<ver>.json`) | CAT.1 |
| T11 | save_file: decode base64url with and without padding; saved bytes equal; `..`, `a/b`, `a\b`, `CON`, `x:y`, trailing dot, 256-byte name refused; existing file not overwritten (suffix `_1`); pre-placed symlink at the target name not followed; over-size refused before decode; unset `downloads` refuses; `data` absent from the result | ATTACH.1 |
| T12 | calendar_get_attachment projection on a recorded event body | ATTACH.1 |
| T13 | Catalogue: every shipped `cli`/`mcp` file loads with zero CAP-012 warnings and dispatches to its executor; `public_claims.json` count equals executable capabilities | CAT.1, CLAIM.1 |
| T14 | Egress: `trawl_extract.url` = `http://169.254.169.254/` and `file:///etc/passwd` refused before spawn; `drive_upload.filePath` outside `uploads` (incl. via symlink) refused | SEC |

Real binaries in CI (a separate job, not a required gate for external contributors):
- gws: `npm install -g @googleworkspace/cli@0.22.5` (its postinstall downloads the native binary, so
  `--ignore-scripts` cannot be used; pinned version, run in the CI sandbox only), then every T1 argv
  plus `--dry-run` must exit 0 and print `"dry_run": true`. This proves the flags exist.
- pact-mcp (`pact-agents[mcp]==1.2.0`) and openpencil-mcp (`@open-pencil/mcp@0.15.1`): live
  `tools/list` must match the recorded snapshot (catches snapshot drift).
- pyghidra-mcp (needs Ghidra and a JDK), cloudflare (needs an account), trawl and metacognition (not
  published binaries): snapshot or argv golden only.

Mutants (lane rule): remove the `--` insertion; textual instead of typed JSON substitution; skip the
pin gate; inherit env; follow symlinks on save. Each must turn a named test red.

## 9. Decisions needed (lead / operator)

Until decided, the affected capabilities load, are refused at call time with `not executable: <reason>`,
and are excluded from the public count. Nothing is removed without operator approval.

- **D1 `desktop_event_bus`**: no tool anywhere implements it (axterminator 0.10.2 has no event-bus
  tools; a subscription is a stream, which a request/response capability cannot carry). Options: (a)
  remove; (b) keep non-executable and file the feature against axterminator. Recommend (b) for 4.0.
- **D2 `cloudflare_manage`**: the declared package does not exist. With the real
  `@cloudflare/mcp-server-cloudflare@0.2.0`, 5 of 12 operations work (`list_zones`, `list_workers`,
  `deploy_worker`, `list_r2_buckets`, `list_r2_objects`). DNS (4), WAF (2) and cache purge have no tool.
  Options: (a) narrow the enum and description to the 5; (b) add REST capabilities for DNS/WAF/purge
  against the Cloudflare v4 API (new files, existing REST executor). Recommend (a) + (b) as a follow-up.
- **D3 `cisco_scanner`**: no MCP server exists; only `scan_mcp_server` maps (`mcp-scanner remote
  --server-url=`). Options: (a) narrow to that one operation as `service: cli`; (b) remove. Recommend (a).
- **D4 `pyghidra_reverse`**: pyghidra works on binaries imported into its project (`binary_name`), so
  `binary_path` maps to `import_binary` then the analysis tool by base name; `binary_path` is limited to
  the `uploads` root (§6.2). Recommend accept.
- **D5 Windows process-tree kill**: Job object needs `unsafe` FFI (precedent `src/win_acl.rs`).
  Recommend accept: without it a timed-out gws on Windows leaves its native child running.
- **D6 Defaults**: `process_execution: enabled` and the shipped-command allowlist on by default, so the
  shipped catalogue works out of the box; operators can disable. Recommend accept.
- **D7 Schema changes** on capabilities that never ran (§2.1, §7): `docs_write` loses `title`,
  `gmail_reply` loses `threadId`, `chat_send` loses `threadKey`, `drive_upload` loses `mimeType`,
  `gmail_save_attachment` loses `output_dir`. No working caller can depend on them. Recommend accept,
  each listed in UPGRADING.

## 10. Delivery (WIP 1, each PR: red tests on CI, implementation, two seats, mutants, merge)

1. This design (docs only).
2. CLI executor: `CliConfig`, typed substitution, spawn/caps/timeout/group kill, execution gate,
   `process_commands`, `process_execution`, `integrity` (T2-T8, T14). Bases on #2683 (MIK-7775) once
   merged, since that PR moves the providers deserializer to `definition/providers.rs`.
3. MCP executor: `McpConfig`, tool selector, executor-owned backends, idle stop (T9, T10).
4. `save_file` and the calendar projection (T11, T12).
5. Catalogue: fix and re-pin the 25 files per §2 and the decisions, real-binary CI job, T1, T13,
   public counts (README, `benchmarks/public_claims.json`, `capabilities/README.md`, docs).

Rollback: revert the executor commits; `cli`/`mcp` services then return to the documented refusal.
