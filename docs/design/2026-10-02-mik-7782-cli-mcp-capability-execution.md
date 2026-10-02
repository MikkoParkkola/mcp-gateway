# MIK-7782: executing `service: cli` and `service: mcp` capabilities

Status: draft for review (round 2; round 1: gpt and grok SHIP-WITH-FIXES, all findings applied). Operator ruling 2026-10-02 (chat): "build and fix, we need to deliver
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
| `trawl_extract` | `trawl` (Go/cobra, operator repo) | `args_template` is Liquid, never read; no dial-time egress control | structured args, URL after `--`; runnable only after D8 |
| `metacognition_verify` | `metacognition` 0.7.0 (clap) | positional text reads `@file`, `setup` runs a subcommand | text on **stdin** (`-`), never argv |
| `openpencil_design` | `openpencil-mcp` 0.15.1, 106 tools | 5 of 8 operations name no real tool | operation-to-tool map: `create_node`→`create_shape`, `export_png`→`export_image`, `set_auto_layout`→`set_layout`, `get_design_tokens`→`design_to_tokens`, `list_components`→`get_components` |
| `pact_contracts` | `pact-mcp` (pact-agents 1.2.0), 7 tools | names differ; every tool takes `project_dir`, which the capability lacks (the server would read its own cwd) | map `verify_contract`/`validate_gate`→`pact_validate`, `list_contracts`→`pact_contracts`, `get_contract`→`pact_contract{component_id}`, `check_budget`→`pact_budget`, `get_retrospective`→`pact_retrospective`, `resume_run`→`pact_resume` (starts a paid run: `read_only: false`); add `project_dir` (limited to a configured root, §6.2) |
| `pyghidra_reverse` | `pyghidra-mcp` 0.2.7 | tool and argument names differ; needs Ghidra + JDK | map `decompile`→`decompile_function`, `get_xrefs`→`list_xrefs`, `get_call_graph`→`gen_callgraph`, `search_symbols`→`search_symbols_by_name`, `disassemble`, `analyze_binary`→`import_binary`; test double in CI |
| `cloudflare_manage` | declared `npx @anthropic/cloudflare-mcp`: **package does not exist** | real `@cloudflare/mcp-server-cloudflare` 0.2.0 has zones, workers, R2; **no DNS, WAF or cache-purge tools** | 5 of 12 operations mappable; 7 need a decision (§9) |
| `cisco_scanner` | `cisco-ai-mcp-scanner` 4.8.5 | **ships no MCP server** (CLI `mcp-scanner` + REST API); no skill scanning | 1 of 5 mappable: `scan_mcp_server` as `service: cli` `mcp-scanner remote --server-url=<url> --raw` (URL egress-checked; the `stdio` subcommand runs a command and is never reachable); 4 need a decision (§9) |
| `desktop_event_bus` | `axterminator mcp serve` 0.10.2, 62 tools | **no event-bus tools**; subscriptions are a stream, not request/response | not executable; decision (§9) |

### 2.1 gws argument fixes

`calendar_insert`: `--calendar`, repeated `--attendee`. `docs_write`: `+write --document --text`.
`drive_upload`: raw `drive files create --upload=<path> --upload-content-type=<mime>` with `name`,
`parents` and `mimeType` in `--json` (keeps every declared field). `gmail_reply`: `+reply` threads from
the message id. `chat_send`: raw `chat spaces messages create` (keeps `threadKey`). `gmail_send`: map
the declared `cc`/`bcc`. Eight raw-API files build
`--params`/`--json` by pasting strings into JSON text; they move to structured JSON arguments (§3.2).
Field-level outcomes are in D7 (§9); each schema change is listed in UPGRADING and the changelog.

## 3. Config schemas

`providers.<name>.config` stays the YAML key. `ProviderConfig.config` is a `RestConfig` by the time
`protocol_config()` runs (serde has already dropped unknown keys), so the typed configs are built at
LOAD: the providers deserializer (`src/capability/definition/providers.rs`, introduced by #2683) reads
`config` as a raw mapping when `service` is `cli` or `mcp` and deserializes it into `CliConfig` or
`McpConfig` with `#[serde(deny_unknown_fields)]`, stored in a new `ProviderConfig.process:
Option<ProcessConfig>` (serialized back under `config`, so the YAML round-trip tests hold). A bad key
is a load error naming the file. `ProtocolConfig::Cli(Box<CliConfig>)` and
`ProtocolConfig::Mcp(Box<McpConfig>)` replace the placeholder comment at `definition/mod.rs:624`. The
REST catch-all for other unknown services stays.

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
        - { each: attendees, arg: "--attendee={item}" }  # array property: one bound element per item
        - { json: "--params=", value: { userId: me, q: "{query}", maxResults: "{maxResults}" } }
        - "--"                     # end of options
        - "{filePath}"             # placeholders standing alone are allowed only after "--"
      stdin: "{text}"              # optional; the route for free text into tools that parse @file
      env: [ANTHROPIC_API_KEY]      # allowlist of variable NAMES, resolved via the LiveEnv overlay
      token_env: GOOGLE_WORKSPACE_CLI_TOKEN  # where the resolved auth.key credential goes (§6.3)
      output: json                 # json (stdout must parse) | text (returned as {"text": ...})
      max_output_bytes: 1048576    # default 1 MiB, ceiling 8 MiB, stdout and stderr each
```

The child runs with cwd AND `HOME` set to a fresh empty directory under the gateway's private temp area,
removed after the call (plus `XDG_CONFIG_HOME`, and on Windows `USERPROFILE`/`APPDATA`/`LOCALAPPDATA`,
pointed inside it). A tool therefore cannot fall back to the operator's own logins, keyrings or
dotfiles. Neither cwd nor HOME is configurable; a capability that needs state gets it through `env`.

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
  `each:` takes an array property of strings and emits one `--x={item}` element per item (only the
  bound `--x=` form is accepted for `each`); nothing ever splits a caller string.
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
2. Resolve `command` once per call to an absolute path: an absolute `command` as given; a bare name
   searched on the child's PATH (on Windows PATH x PATHEXT: `.exe`, `.cmd`, `.bat`). The child is always
   spawned by that RESOLVED absolute path, so for a `.cmd`/`.bat` hit std takes its batch-argument
   escaping path (Rust >= 1.77.2, CVE-2024-24576) and refuses arguments it cannot escape; that refusal
   maps to a parameter error. A `command` containing a separator but not absolute is refused. The same
   resolver serves `service: mcp` stdio spawns (npm installs MCP servers as `.cmd` shims too).
3. Spawn through `process-wrap` 10 (watchexec; Apache-2.0 OR MIT; `default-features = false`,
   features `tokio1`, `process-group`, `job-object`, `kill-on-drop`), which puts the child in its own
   process group on Unix and a kill-on-close Job object on Windows behind a safe API. Our crate adds no
   `unsafe` (ADR-016 keeps `src/win_acl.rs` the only unsafe module, lead decision D5). Timeout, cap
   overflow and drop kill the whole tree. This matters: gws's npm entry `run.js` is a node wrapper that
   `spawnSync`s the native gws binary, so killing node alone would orphan it. New transitive crates:
   `nix` (Unix) and `windows` 0.62 (Windows); `cargo deny` and `cargo audit` must pass in the CLI PR.
   Environment: `configure_child_environment` (`stdio.rs:42`, made `pub(crate)`) baseline with HOME and
   the profile directories overridden (§3.1), then only the `env` allowlist resolved through `LiveEnv`
   like `StdRuntimeCommandRunner` (`runtime/provider.rs:662`), then `token_env`. stdin is written in a
   separate task and closed (or null when no `stdin` is configured), so a child that never reads it
   cannot deadlock the call.
4. Read stdout and stderr concurrently, each into a buffer capped at `max_output_bytes`; past the cap
   the child is killed and the call fails `output too large` (never truncated JSON passed on as data).
5. `tokio::time::timeout(provider.timeout)`; on expiry kill the group and fail `timed out after Ns`.
6. Exit mapping: 0 parses stdout per `output`; non-zero fails with `Error::Protocol` carrying the exit
   code and a diagnostic excerpt; a signal death says so. gws prints a JSON error object on stdout on
   failure (exit 2 = auth): when stdout parses as JSON with an `error` key, its `message` is the
   excerpt, else the last 2 KiB of stderr. The excerpt is redacted BEFORE truncation: every injected
   env and `token_env` value and every argv/stdin value of 8+ bytes is replaced by `[redacted]`
   (literal match), then the firewall redactor (`security/firewall/redactor.rs`
   `scan_and_redact`) runs on it, the same scanner the output firewall uses.
7. Concurrency: a per-capability semaphore (default 4) bounds simultaneous children.

Long-running calls: the existing task mode (`B3`) applies unchanged because the executor is reached
from the same dispatch; nothing new.

## 5. MCP execution

New `src/capability/executor/mcp.rs` (`McpExecutor`). No new MCP client: each `service: mcp`
capability gets one `crate::backend::Backend`, built with `Backend::new` from a `BackendConfig`
(`TransportConfig::Stdio` with `join_command(command, args)`, or the HTTP transport for `url`), with
`env` filled from the allowlist, `timeout` from the provider, and:

- **Per-caller children.** The executor's map is keyed by (capability, caller binding), the same
  opaque binding the invoke path derives for `identity_key`; each key owns its own `Backend`, i.e. its
  own server process, so user B never sees user A's open documents, projects or pyghidra imports.
  (Backends get per-user slots only through `identity_propagation` (`src/backend/pool.rs:261`), which
  also brings a credential strategy and audience that a local stdio server has no use for, so it is
  not borrowed for this.) On a multi-user gateway a call with no caller binding is refused; a
  single-user gateway uses one shared key. At most 16 children per capability; the least recently used
  is stopped to admit a new one.
- **cwd** is a private empty directory per capability (never the gateway's working directory, which
  `StdioTransport` inherits when `cwd` is None, `stdio.rs:187-190`); HOME as in §3.1.
- **Process tree.** The stdio spawn gains an ownership option (enum `ChildTree::DirectChild |
  OwnedTree`, default `DirectChild` so configured backends are unchanged) and capability backends use
  `OwnedTree`, the same `process-wrap` group/Job ownership as the CLI path, so stop, unload and shutdown
  also end wrapper-launched descendants (`npx` → node).
- **Bounded frames.** `StdioTransport`'s reader (`BufReader::lines()`, `stdio.rs:240`) has no line limit
  today, for every stdio backend. It becomes a bounded line read (default 16 MiB, raised by
  `max_frame_bytes`); an oversized frame kills that child and fails pending requests. This is a fix to
  the shared transport, not a capability-only guard.
- **Idle stop** reuses `BackendConfig.stop_when_idle_for` (5 min) and the existing `stop_if_idle` sweep
  (`gateway/server/mod.rs:3665-3676`), run over the private map as well; no second clock.
- Ownership: a `McpCapabilityBackends` map ((capability, binding) to `Arc<Backend>`) owned by the
  `CapabilityExecutor`, created lazily. It is NOT registered in `BackendRegistry` (it must not appear as
  a public server). Entries are stopped when the capability is unloaded or reloaded with a different
  definition hash, and on shutdown.
- Call: resolve the tool and arguments (§3.3), `backend.request_with_headers("tools/call", {name,
  arguments})` on the caller's child. A JSON-RPC error or `isError: true` maps to `Error::Protocol` with the
  tool's text (redacted as in §4.6). `structuredContent` is returned when present, else the content.
- **Prepare step** (pyghidra only today): a selector entry may carry `prepare: { tool, arguments,
  bind: { <arg>: <result field> } }`, one extra `tools/call` on the same per-caller child whose result
  field is passed to the main call. `analyze_binary`/`decompile`/... first call `import_binary` with the
  root-checked `binary_path` and bind the program name it returns; nothing is keyed on a base name the
  caller chose. The exact result field is pinned by the T10 snapshot of pyghidra-mcp 0.2.7.
- The tool list is never exposed: the capability is the unit callers see and govern.

## 6. Security model

### 6.1 Execution gate (fail closed, checked on every call before any spawn or connect)

1. **Pinned and verified.** `CapabilityDefinition` gains `#[serde(skip)] integrity: Integrity`
   (`Unpinned` | `Verified`), whose `Default` is `Unpinned`. Only `parse_capability_file` sets
   `Verified`, and only after a present pin matched. A definition built any other way (code, a
   deserialize outside the parser, a test) is `Unpinned`. A `cli`/`mcp` definition that is `Unpinned` is
   refused with `capability '<n>' must be pinned (mcp-gateway cap pin) to run a local process`. A
   mismatched pin never loads (existing behaviour) and a pin changed on disk unloads the capability
   (existing rug-pull path) and stops its MCP children.
2. **Exact invocation allowlist.** A pin only proves integrity, so config `capabilities.process_commands`
   lists what may run, each entry `{ command, args_prefix }` compared EXACTLY against the pinned YAML:
   `command` is the YAML string itself (a bare name or an absolute path, never a resolved basename,
   never a name prefix), and `args_prefix` must equal the YAML's leading static args element by element.
   Defaults (the shipped catalogue): `gws []`, `metacognition []`, `trawl []`, `openpencil-mcp []`,
   `pact-mcp []`, `pyghidra-mcp []`, `axterminator [mcp, serve]`, `npx [-y,
   @cloudflare/mcp-server-cloudflare@0.2.0]` (the full args list: nothing may precede or follow the
   package), `mcp-scanner [remote]`. A non-matching definition is refused at call time and reported by
   `cap validate`. Operators extend the list for their own capabilities.
3. **Kill switch.** `capabilities.process_execution: enabled | disabled` (enum, default `enabled`, lead
   decision D6), hot reloadable, refuses all `cli`/`mcp` calls when disabled. UPGRADING and SECURITY
   state that shipped `cli`/`mcp` files, inert before 4.0, become live process execution on upgrade, and
   name this switch. The per-capability kill switch and disable (`dispatch_guards.rs:112`) and the
   error-budget auto-kill already apply because the gate keys on the capability name.
4. Personal-account, identity and OAuth-isolation validation (`execution_context.rs:369`,
   `validate_oauth_isolation`) run as for REST.

### 6.2 Inputs and outputs

- Input firewall, audit record, caller identity and output firewall come from the shared invoke wrapper
  (fact 3). The executor adds to the audit record's detail: command name (never argv values),
  exit code, duration, bytes out.
- Egress parameters (`trawl_extract.url`; `cisco_scanner.target` if D3 keeps it) are declared
  `format: uri` with `egress: true`. Two layers, both required before such a capability may run:
  (a) before spawn, the gateway resolves the host (A/AAAA) and refuses any address the REST
  `PinningResolver` deny list refuses, besides the literal check of `validate_url_not_ssrf` (which
  lets hostnames through, `security/ssrf/mod.rs:245`); (b) connect-time enforcement inside the child,
  because the child re-resolves (rebinding) and follows redirects (Go's default client follows 10).
  Layer (b) does not exist today: trawl builds its own `http.Transport` with no proxy or dial hook
  (`trawl/internal/fetch/fetcher.go:49`). So `trawl_extract` stays refused (`not executable: egress
  cannot be enforced`) until trawl ships a dial-time private-address refusal that the capability
  always passes; decision D8. No egress capability runs on the pre-check alone.
- Local file parameters: `gws_drive_upload.filePath` reads any file the gateway user can read, and a
  remote caller could upload `~/.ssh/id_ed25519`. A path property declares `path_root: <name>`; the value
  is canonicalized (symlinks followed) and must satisfy `canonical.strip_prefix(root_canonical)` (a
  component-wise check, so `/srv/uploads_evil` is not inside `/srv/uploads`), with `root_canonical`
  from `capabilities.files.<name>`. Roots have no default: an unset root makes the capability refuse
  with a message naming the key. Used by `gws_drive_upload.filePath` (`uploads`),
  `pyghidra_reverse.binary_path` (`uploads`), `pact_contracts.project_dir` and
  `openpencil_design.file_path` (`projects`), and `downloads` for §7.

### 6.3 Credentials and secrets (CWE-532)

- **Caller credentials, not the operator's login.** As shipped, every gws file has `auth` with no `key`,
  so gws would run on whatever login sits in the gateway user's `~/.config/gws`, for every caller, and
  `validate_oauth_isolation` (which keys on `oauth:`) would never fire. The gws files get
  `auth.key: oauth:google` (as the REST Google capabilities have), so the existing token resolution,
  personal-account and OAuth-isolation checks apply unchanged; the executor passes the resolved
  access token in `token_env` (`GOOGLE_WORKSPACE_CLI_TOKEN`, gws's highest-priority credential source)
  and sets `GOOGLE_WORKSPACE_CLI_CONFIG_DIR` inside the per-call empty HOME, so there is no fallback
  credential. A call whose token does not resolve fails before spawn.
- Secrets reach a child only through `env`/`token_env`, never argv (argv is visible in `ps`) or stdin.
  The validator refuses `{env.X}` or `{access_token}` placeholders in `args`/`stdin` (new check).
- Logs and errors carry the command name, never argv, stdin or env values; diagnostic excerpts are
  redacted as in §4.6. New structs holding env or token values get a manual `Debug`.
  `cwe532-leak-lint.py` runs unchanged in CI.
- `cloudflare_manage` today writes `{env.CLOUDFLARE_API_TOKEN}` into an env mapping; under whatever D2
  decides it becomes the allowlist entry `CLOUDFLARE_API_TOKEN`.

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
- Aggregate: `capabilities.files.downloads_quota_bytes` (default 1 GiB) bounds the directory. Before a
  write the executor sums the sizes of the root's regular files (one `read_dir`, no recursion) and
  refuses when the new file would exceed the quota; nothing partial is left.
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
| T2 | Hostile values through the real spawn path (argv_echo): `--attach=/etc/passwd`, `-a x`, `--draft`, `; rm -rf ~`, `$(id)`, backticks, `%PATH%`, `"`, newline, NUL, `@/etc/passwd`, `setup`, a 1 MiB string, non-ASCII. Assert: each value appears as exactly the bytes of ONE argv element (or stdin), argv length equals the golden length, or the call is refused with a parameter error; never an extra element. Run on BOTH an `--x={p}` element and a standalone positional after `--` (the `--`-insertion mutant's red target: with `--` removed, `--draft` as the positional must be seen as an option by `opt_parse.py`, a double that parses options like clap and reports what it parsed). `@/etc/passwd` and `setup` go through `stdin` for metacognition and must not reach argv | CLI.1 |
| T3 | JSON args: `"q": "x\", \"userId\": \"evil"` stays one string; numbers stay numbers; absent optional key dropped | CLI.1 |
| T4 | Env: child sees only the baseline plus allowlisted names and `token_env`; a gateway variable `SECRET_X` absent; HOME, cwd and `GOOGLE_WORKSPACE_CLI_CONFIG_DIR` are the empty per-call dir, which is gone after the call | CLI.1, SEC |
| T5 | Timeout kills the child and its grandchild (Unix: the grandchild's pid is gone); stdout cap kills and errors; non-zero exit maps to an error with the code; gws-style JSON error message surfaces | CLI.1 |
| T6 | Windows (`cfg(windows)` job): a `gws.cmd` double on PATH resolves and the spawned program path ends in `.cmd`; hostile values T2 (incl. `%PATH%`, `^`, `&`, `"`) through the `.cmd` either arrive intact or are refused; a timed-out `.cmd` that started a child leaves no process (Job object); an MCP `.cmd` shim starts | CLI.1 |
| T7 | Unpinned `cli` and `mcp` definitions refused before spawn (argv_echo leaves a marker file; assert absent), including a definition constructed in code without the parser (default `Unpinned`); tampered pin never loads; `process_commands` mismatches refused: other command, same basename at another path, extra leading arg (`npx --yes -p evil ...`), `mcp-scanner stdio`; `process_execution: disabled` refuses | SEC.1 |
| T8 | A canary in argv, stdin, an env value and the token never appears in captured tracing output, the audit record or the error text, including when the double echoes all of them to stderr and to a JSON `error.message` on stdout and exits 1 | SEC |
| T9 | MCP: each shipped `mcp` file run against fake_mcp with its server's recorded snapshot; operation maps to the expected tool name and arguments; unknown operation refused; tool `isError` maps to an error; one child reused across calls by ONE caller, a second caller gets a different child (pid differs), no binding on a multi-user gateway refused; children stopped on unload, idle and shutdown, including a grandchild the fake server spawned; child cwd is the private dir; a newline-free 20 MiB frame kills the child and errors; pyghidra prepare step binds the name the snapshot's `import_binary` returns | MCP.1, CAT.1 |
| T10 | Snapshot conformance: every mapped tool exists in the recorded `tools/list` of the pinned server version (`tests/fixtures/cap_exec/snapshots/<server>@<ver>.json`) and the arguments each operation generates (from typical inputs) validate against that tool's full `inputSchema` (required keys, types) | CAT.1 |
| T11 | save_file: decode base64url with and without padding; saved bytes equal; `..`, `a/b`, `a\b`, `CON`, `x:y`, trailing dot, 256-byte name refused; existing file not overwritten (suffix `_1`); pre-placed symlink at the target name not followed; over-size refused before decode; quota exceeded refused with no partial file; unset `downloads` refuses; `data` absent from the result | ATTACH.1 |
| T12 | calendar_get_attachment projection on a recorded event body | ATTACH.1 |
| T13 | Catalogue: every shipped `cli`/`mcp` file loads with zero CAP-012 warnings and dispatches to its executor; `public_claims.json` count equals executable capabilities | CAT.1, CLAIM.1 |
| T14 | Egress: `http://169.254.169.254/`, `file:///etc/passwd` and a hostname resolving to 127.0.0.1 (`localhost`) refused before spawn; a capability with an `egress: true` parameter and no connect-time enforcement refused (D8); path roots: `/uploads_evil/x` vs root `/uploads`, `../` escape and a symlink inside the root pointing out are refused | SEC |

Real binaries in CI (a separate job, not a required gate for external contributors):
- gws: `npm install -g @googleworkspace/cli@0.22.5` (its postinstall downloads the native binary, so
  `--ignore-scripts` cannot be used; pinned version, run in the CI sandbox only), then every T1 argv
  plus `--dry-run` must exit 0 and print `"dry_run": true`. This proves the flags exist.
- pact-mcp (`pact-agents[mcp]==1.2.0`) and openpencil-mcp (`@open-pencil/mcp@0.15.1`): live
  `tools/list` must match the recorded snapshot (catches snapshot drift).
- pyghidra-mcp (needs Ghidra and a JDK), cloudflare (needs an account), trawl and metacognition (not
  published binaries): snapshot or argv golden only.

Mutants (lane rule): remove the `--` insertion (T2 positional row); textual instead of typed JSON
substitution (T3); skip the pin gate (T7); inherit env or HOME (T4); `starts_with` instead of
`strip_prefix` (T14); follow symlinks on save (T11); a shared MCP map key (T9). Each must turn its named
test red.

Catalogue claims (CLAIM.1) count a `cli`/`mcp` capability only when its real-tool conformance row above
is green or, for tools not installable in CI, its snapshot or golden row is; capabilities held by §9
decisions are not counted.

## 9. Decisions needed (lead / operator)

Until decided, the affected capabilities load, are refused at call time with `not executable: <reason>`,
and are excluded from the public count. Nothing is removed without operator approval.

- **D1-D3 `desktop_event_bus`, `cloudflare_manage`, `cisco_scanner`** (operator, 2026-10-02: "find out
  what broken capabilities could be replaced with something working"): a research lane is finding working
  replacements. Facts for it: axterminator 0.10.2 has no event-bus tools; the declared
  `@anthropic/cloudflare-mcp` does not exist and the real `@cloudflare/mcp-server-cloudflare@0.2.0`
  covers 5 of 12 operations (zones, workers, R2; no DNS, WAF or purge); `cisco-ai-mcp-scanner` 4.8.5 has
  no MCP server and maps 1 of 5 operations. These three are not narrowed, removed or re-described here.
- **D4 `pyghidra_reverse`** (lead: ACCEPTED): `binary_path` (root-checked) goes to `import_binary` in a
  prepare step on the caller's own child; the analysis tool gets the program name the import returned.
- **D5 Windows process-tree kill** (lead: safe crate first; ADR-016 keeps `src/win_acl.rs` the only
  unsafe module): `process-wrap` 10.0.1 (watchexec, updated 2026-09-23, Apache-2.0 OR MIT) exposes Job
  objects and Unix process groups through a safe API. `cargo deny`/`cargo audit` evidence goes in the CLI
  PR; if either rejects it, an ADR amending ADR-016 goes to two seats and then the operator, before code.
- **D6 Defaults** (lead: ACCEPTED): `process_execution: enabled`, the exact allowlist of §6.1.2 on by
  default, unpinned `cli`/`mcp` always refused; default and switch documented in UPGRADING and SECURITY.
- **D7 Schema changes** (lead: ACCEPTED per field, only where the real CLI cannot do it; each in
  UPGRADING). Checked against gws 0.22.5:
  - `chat_send.threadKey`: KEPT, via the raw `chat spaces messages create` with
    `thread.threadKey` and `messageReplyOption` (dry-run verified); the file moves off `+send`.
  - `drive_upload.mimeType`: KEPT, via raw `drive files create --upload=<path>
    --upload-content-type=<mime>` (metadata `mimeType` also converts to Google formats); off `+upload`.
  - `gmail_reply.threadId`: DROPPED; `+reply` derives the thread from `messageId`, so nothing is lost.
  - `docs_write.title`: DROPPED; a title exists only on `documents.create`, a separate call, and one
    capability is one call. `documentId` becomes required.
  - `calendar_insert.attendees`: becomes an array emitted as repeated `--attendee=` (§3.2 `each`).
  - `gmail_save_attachment.output_dir`: DROPPED; writes go only to the configured `downloads` root (§7).
- **D8 `trawl_extract` egress**: the gateway cannot stop a child from following a redirect or a DNS
  rebind to a private address. trawl (operator repo) needs a dial-time refusal of private/reserved
  addresses (a `net.Dialer.Control` hook, also for its headless-browser path) behind a flag the
  capability always passes. Until such a trawl release exists, `trawl_extract` is refused and not
  counted. Recommend: make the trawl change (small, owned) as a follow-up ticket.

## 10. Delivery (WIP 1, each PR: red tests on CI, implementation, two seats, mutants, merge)

1. This design (docs only).
2. CLI executor: `CliConfig` (load-time typed), typed substitution, `process-wrap` spawn with
   caps/timeout/tree kill, HOME isolation, `token_env`, redaction, execution gate, `process_commands`,
   `process_execution`, `integrity`, path roots, egress pre-check (T2-T8, T14). Bases on #2683 (MIK-7775) once
   merged, since that PR moves the providers deserializer to `definition/providers.rs`.
3. MCP executor: `McpConfig`, tool selector and prepare step, per-caller executor-owned backends,
   private cwd, owned process tree, bounded stdio frames (shared transport fix), idle stop (T9, T10).
4. `save_file` and the calendar projection (T11, T12).
5. Catalogue: fix and re-pin the 25 files per §2 and the decisions, real-binary CI job, T1, T13,
   public counts (README, `benchmarks/public_claims.json`, `capabilities/README.md`, docs).

Rollback: revert the executor commits; `cli`/`mcp` services then return to the documented refusal.
