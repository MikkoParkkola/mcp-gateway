# Gateway Secret Redaction and Pinned npm Runtime Design

**Goal:** Remove pre-deployment secret exposure from gateway CLI/API/status/logging surfaces and define a reproducible, immutable local runtime for the four enabled npm MCP backends that currently depend on `npx` network installation.

**Scope:** This design changes only the isolated public recovery branch. It does not modify the dirty private repository, live gateway configuration, shared npm cache, running gateway process, launchd state, or ports.

## Confirmed root causes

1. `BackendInfo` copies `BackendConfig.env` as `HashMap<String, String>`, derives `Serialize` and `Debug`, and is used by both JSON listing and `mcp-gateway get`. It also copies raw command strings and URLs, allowing inline arguments, URL userinfo, query values, and fragments to escape through the same surfaces.
2. `mcp-gateway get` iterates that map and prints `KEY=value` directly. Header values are absent from this DTO today, so an attempted header audit cannot even show safe presence information.
3. `BackendStatus` itself does not contain environment or header maps, but no sentinel regression proves that constructing status from a secret-bearing backend remains value-free.
4. The HTTP transport logs raw MCP session identifiers when sending, extracting, and storing sessions. It also logs the complete SSE endpoint, every response header and value when no session header exists, and embeds non-success response bodies in `Error::Transport`; those errors are routinely logged by callers.
5. Four enabled stdio backends use `npx -y` and are absent from the existing local npx cache, so first start depends on mutable registry state and network availability.

## Security DTO and CLI design

`BackendInfo` will expose only deterministic key-name inventories:

- `env: Vec<String>` contains sorted environment-variable names.
- `headers: Vec<String>` contains sorted configured header names.
- Neither field contains a secret value or a value fingerprint.
- `command` becomes a structured summary containing only the parsed executable and argument count. Shell arguments are never serialized or printed; an unparseable command produces a fixed invalid-command marker.
- `url` is normalized to scheme, host, effective port, and path. URL username, password, query, and fragment are removed before the value reaches `BackendInfo`.

The human `get` output will render each key name with a literal `<set>` presence marker, the executable with a redacted argument count, and only the sanitized URL. JSON list/get serialization will use the same safe structures. Existing transport, description, and enabled fields remain unchanged.

`BackendConfig` keeps its existing manually redacted `Debug` implementation. A backend constructed with distinct environment, header, command-argument, URL-userinfo, URL-query, and URL-fragment sentinel values will be converted through `BackendInfo`, CLI execution, and `BackendStatus` serialization; every output must omit the sensitive values while retaining safe key names, executable identity, argument count, and sanitized origin/path.

## HTTP diagnostic design

Operational logs keep state transitions while dropping sensitive payloads:

- Session events record `session_present = true` and the method where useful, never the session identifier.
- SSE endpoint receipt records only that an endpoint was received, never the endpoint or query string.
- A response without `MCP-Session-Id` records status and header count, never header names or values.
- A stored session records only `session_present = true` and a URL sanitized to origin/path.
- Non-success bodies are inspected only to preserve session-expiry classification, then discarded. Returned errors contain HTTP status and, when applicable, the safe phrase `session expired`; no body text is retained.
- Every base/message URL used in an HTTP log or transport error passes through one sanitizer that removes userinfo, query, and fragment. Request-library errors are reduced to safe timeout/connect/status categories rather than interpolated with their raw URL-bearing display text.

Session-expiry recovery remains behaviorally compatible: HTTP 404 is classified by status, and bodies containing JSON-RPC code `-32015` or `session not found` are converted to the safe `session expired` marker before leaving the transport boundary.

Captured tracing tests will send unique sentinels in a configured URL userinfo/query/fragment, an MCP session ID, SSE endpoint query, command argument, credential response header, and non-success response body. CLI text, API JSON, captured logs, status JSON, and returned error text must omit every sentinel while still containing useful status/presence metadata.

## Pinned npm runtime design

The recovery bundle contains one lock graph for four exact direct dependencies, using registry metadata observed on 2026-07-21:

| Backend | Package | Exact version | Direct-package SRI |
|---|---|---:|---|
| context7 | `@upstash/context7-mcp` | `3.2.4` | `sha512-w2Vg6MkF4Qojp8X1fdmJ6NrjZ8Ip/9lflybtqfDKaqOsUV9iVaXeRbyGTqARdn1O8teIPm7Bt+nfVqFiUcZvjQ==` |
| sequential-thinking | `@modelcontextprotocol/server-sequential-thinking` | `2026.7.4` | `sha512-tmR/ieGaeweffLNBrDp1H1w4sn4M6TN5yWSbMS+YMfS+0GDyPjnNKzqCl2uqfdRiX3D44PJUhwiDGqtJp6tFhw==` |
| filesystem | `@modelcontextprotocol/server-filesystem` | `2026.7.10` | `sha512-Mmjg4anFBD5OzbPnGJOA0jPPN8645ERhQk38HQLpSenx1ox9bfdPkmAzUnNjeQtqQGFLtKe13J20RtLBmUKMZA==` |
| morphllm | `@morphllm/morphmcp` | `0.8.206` | `sha512-2yVRtx7NLeTlN6WqQb25UA4dobeZtZ2jQMLSNyeR367VHRP4n6vV4bfNjtfQKyHQiG/6refu12923Rkinf3bpw==` |

The committed recovery directory will contain:

- `package.json` with exact dependency versions and no ranges.
- npm lockfile v3 with resolved tarballs and SRI for the full dependency graph.
- `pins.json` with expected direct versions, SRI values, package bin names, and relative JavaScript entrypoints.
- `pins.json` also records darwin/arm64, Node `v26.5.0`, npm `11.17.0`, `/opt/homebrew/bin/node`, `/opt/homebrew/bin/npm`, SHA-256 expectations for their resolved runtime files, and a canonical digest for the complete npm module tree. npm is invoked through the pinned Node binary, never through `env node`.
- A verifier that rejects ranges, missing lock integrity, unexpected versions, escaping symlinks, missing bin targets, non-absolute Node/entrypoint commands, and a mismatch between two independently installed content trees.
- A bootstrap that runs `npm ci --ignore-scripts --no-audit --no-fund` with an explicitly supplied empty staging cache. It never reads or writes the user's shared npm cache and never deletes an existing directory.
- A stdio smoke client that runs each entrypoint with `/opt/homebrew/bin/node`, performs MCP `initialize`, sends `notifications/initialized`, and requires a successful `tools/list` response. The filesystem server receives only the currently configured safe roots `/Users/mikko/github` and `/Users/mikko/Documents`. Morph receives a fixed non-secret placeholder solely because it hides all tool definitions when the API-key variable is absent; this smoke does not validate live credentials.
- An audit step runs `npm audit --json` against the locked graph, records the report and exit status as staging evidence, and never invokes `npm audit fix` or rewrites a pin.

## Immutable installation and activation

Bootstrap installs into a unique staging directory, verifies the lock graph and bins, and computes a canonical SHA-256 content-tree digest from relative paths, file bytes, executable bits, and symlink targets while ignoring timestamps. A second clean install uses a different newly created empty cache and staging directory and must produce the same digest. Successful and failed staging trees, cache roots, audit reports, version records, and verifier output are retained under the explicitly supplied recovery evidence root; the bootstrap never cleans, overwrites, or reuses an existing path.

The production publish location is:

`/Users/mikko/.local/libexec/mcp-gateway/npm-runtime/<tree-digest>`

For a future publish, the verified object must first be staged at a unique retained path under the production publish root. Publication removes all write bits from the staged root, directories, and regular files, recomputes the digest, and then performs one atomic, exclusive `symlink(2)` creation from `<tree-digest>` to that pre-positioned object. Unlike ordinary `rename(2)`, symlink creation fails with `EEXIST` even if another process races to create an empty destination, so an existing digest path is never overwritten. After alias creation, publication verifies the alias identity and target, contained symlinks, sealed modes, and canonical content digest through the published path. A detected concurrent mutation fails publication and removes the just-created alias only when its recorded filesystem identity and target are unchanged.

Mode-bit sealing protects against accidental writes, not a hostile process running as the same owner. The owner can restore write permission, and a writable file descriptor opened before sealing remains writable; post-publication verification detects such a mutation only when it occurs during the observed publication window. The future publisher therefore has an explicit same-owner trust boundary: it must exclude hostile or uncoordinated processes under that UID before publishing and while the object is in use. Absolute immutability would require a stronger separately owned or read-only storage boundary that is outside this recovery task. Generated gateway commands pin the literal digest alias and no mutable `current` link is required. This recovery task does not pre-position an object or create the alias.

Rollback retains the previous immutable directory and reviewed snippet. It consists of selecting the earlier snippet during a separately authorized gateway configuration deployment; this recovery task performs neither activation nor configuration replacement.

The generated reviewed snippet uses these command shapes:

- `/opt/homebrew/bin/node /Users/mikko/.local/libexec/mcp-gateway/npm-runtime/<tree-digest>/node_modules/@upstash/context7-mcp/dist/index.js`
- `/opt/homebrew/bin/node /Users/mikko/.local/libexec/mcp-gateway/npm-runtime/<tree-digest>/node_modules/@modelcontextprotocol/server-sequential-thinking/dist/index.js`
- `/opt/homebrew/bin/node /Users/mikko/.local/libexec/mcp-gateway/npm-runtime/<tree-digest>/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js /Users/mikko/github /Users/mikko/Documents`
- `/opt/homebrew/bin/node /Users/mikko/.local/libexec/mcp-gateway/npm-runtime/<tree-digest>/node_modules/@morphllm/morphmcp/dist/index.js`

Here `<tree-digest>` is not a user-supplied placeholder: the generator accepts only a retained evidence root, replays toolchain/tree/smoke/audit verification, derives the canonical digest internally, and fails if any resulting executable or argument path is not absolute. Its output is a command-only merge fragment with no environment, header, enabled-state, description, or timeout values; applying it later must preserve the complete private configuration and recovered process environment.

## Test and commit boundaries

1. Commit the reviewed design and implementation plan.
2. Write failing CLI/API/status sentinel tests, observe the leaks, implement name-only DTOs/output, rerun targeted tests, and commit.
3. Write failing captured-log sentinel tests, observe the leaks, implement metadata-only diagnostics and safe session-expiry errors, rerun targeted tests, and commit.
4. Add the exact npm manifest, generate the lock through an isolated cache, add verifier/bootstrap/smoke tests, perform two clean staging installs with separate empty caches, record the Node/npm hashes and npm-audit result, and commit only manifests and tooling—not `node_modules`, caches, audit output, or generated local snippets.
5. Run format, clippy with warnings denied, the full all-features test suite, locked release build, leak lint, static caller review, and pre/post-commit diff checks.

## Known boundary

Repository instructions require GitNexus impact and change analysis, but this public worktree has no GitNexus index and no GitNexus MCP tools are available. Creating an index would mutate a cache, which is explicitly prohibited for this recovery task. Static caller searches, Rust compiler errors, targeted tests, the full suite, and manual diff review are the approved fallback; this limitation must appear in the final report.
