# Gateway Secret Redaction and Pinned npm Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every gateway diagnostic surface secret-safe and produce a reproducible, integrity-verified recovery bundle for the four enabled npm MCP backends.

**Architecture:** Replace secret-bearing backend DTO fields with explicit summaries at the source boundary, and reduce HTTP diagnostics to sanitized metadata before values can reach tracing or transport errors. Build the npm runtime from one exact lock graph into two independent staging trees, verify toolchain/package/content hashes and stdio MCP behavior, and generate a reviewed configuration snippet for a digest-addressed immutable install without activating it.

**Tech Stack:** Rust 2024, serde, shlex, url, tracing/tracing-subscriber, Node.js v26.5.0, npm v11.17.0, npm lockfile v3, Node built-in test runner.

## Global Constraints

- Work only in `/Users/mikko/github/.worktrees/mcp-gateway-recovery-upstream` on `recovery/upstream-20260720`.
- Do not mutate `/Users/mikko/github/mcp-gateway-private`, live configuration, shared caches, PID 32084, launchd, or port 39401.
- Do not print secret values while testing; use synthetic sentinels only.
- Use `/opt/homebrew/bin/node` and `/opt/homebrew/bin/npm` with the committed version and SHA-256 expectations.
- Use distinct newly created staging and npm-cache directories for the two deterministic installs; retain all staging evidence and never overwrite or delete an existing path.
- Do not run `npm audit fix`; audit is evidence only.
- Commit reviewable slices after fresh targeted verification.
- GitNexus is unavailable and creating its missing index is prohibited; use static caller searches, compiler feedback, targeted/full tests, and diff review as the documented fallback.

---

### Task 1: Secret-safe backend DTO, CLI, and status serialization

**Files:**
- Modify: `src/gateway/ui/backend_ops.rs`
- Modify: `src/commands/add_remove.rs`
- Modify: `src/backend/tests.rs`
- Create: `tests/cli_secret_redaction.rs`

**Interfaces:**
- Produces: `BackendCommandInfo { executable: String, argument_count: usize }`.
- Produces: `BackendInfo.env: Vec<String>` and `BackendInfo.headers: Vec<String>`.
- Produces: sanitized `BackendInfo.url` containing scheme/host/port/path only.
- Consumes: existing `shlex::split`, `url::Url`, `BackendConfig`, `Backend::status`, and binary `get`/`list --json` commands.

- [ ] **Step 1: Write API DTO sentinel tests**

Add tests in `src/gateway/ui/backend_ops.rs` that construct stdio and HTTP configs with distinct sentinels and assert serialized JSON does not contain values or raw arguments:

```rust
#[test]
fn backend_info_serialization_exposes_only_safe_presence_metadata() {
    let env_secret = "SENTINEL_ENV_VALUE_91d0";
    let header_secret = "SENTINEL_HEADER_VALUE_5a41";
    let arg_secret = "SENTINEL_COMMAND_ARG_72bc";
    let mut cfg = empty_config();
    cfg.backends.insert("stdio-secret".to_string(), BackendConfig {
        transport: stdio_transport(&format!("/usr/bin/example --token {arg_secret}")),
        env: HashMap::from([("SAFE_ENV_NAME".to_string(), env_secret.to_string())]),
        headers: HashMap::from([("Authorization".to_string(), header_secret.to_string())]),
        ..Default::default()
    });

    let json = serde_json::to_string(&get_backend(&cfg, "stdio-secret").unwrap()).unwrap();
    for sentinel in [env_secret, header_secret, arg_secret] {
        assert!(!json.contains(sentinel), "secret escaped BackendInfo: {json}");
    }
    assert!(json.contains("SAFE_ENV_NAME"));
    assert!(json.contains("Authorization"));
    assert!(json.contains("/usr/bin/example"));
    assert!(json.contains("argument_count"));
}

#[test]
fn backend_info_url_removes_userinfo_query_and_fragment() {
    let secret = "SENTINEL_URL_44af";
    let mut cfg = empty_config();
    cfg.backends.insert("http-secret".to_string(), BackendConfig {
        transport: http_transport(&format!(
            "https://user:{secret}@svc.example.com/mcp?token={secret}#{secret}"
        )),
        ..Default::default()
    });
    let json = serde_json::to_string(&get_backend(&cfg, "http-secret").unwrap()).unwrap();
    assert!(!json.contains(secret));
    assert!(json.contains("https://svc.example.com/mcp"));
}
```

- [ ] **Step 2: Write full CLI sentinel tests**

Create `tests/cli_secret_redaction.rs` using `env!("CARGO_BIN_EXE_mcp-gateway")`. Write a temporary YAML with environment/header values, a command argument, and URL userinfo/query/fragment sentinels; invoke both `get` and `list --json`; concatenate stdout/stderr and assert every sentinel is absent while safe key names and `<set>` are present.

- [ ] **Step 3: Write status serialization sentinel test**

In `src/backend/tests.rs`, construct `Backend` from a `BackendConfig` containing all sentinel fields, serialize `backend.status()`, and assert it includes the backend name but none of the sentinels or the field names `env` and `headers`.

- [ ] **Step 4: Run the new tests and verify RED**

Run:

```bash
cargo test --all-features backend_info_serialization_exposes_only_safe_presence_metadata -- --nocapture
cargo test --all-features backend_info_url_removes_userinfo_query_and_fragment -- --nocapture
cargo test --all-features --test cli_secret_redaction -- --nocapture
cargo test --all-features status_serialization_omits_backend_config_secrets -- --nocapture
```

Expected: DTO and CLI tests fail by showing synthetic sentinels; the status test may already pass and then acts as a characterization guard requiring no production change.

- [ ] **Step 5: Implement the minimal DTO boundary**

In `src/gateway/ui/backend_ops.rs`, add the safe command structure and private summarizers:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendCommandInfo {
    pub executable: String,
    pub argument_count: usize,
}

fn summarize_command(command: &str) -> BackendCommandInfo {
    match shlex::split(command) {
        Some(parts) if !parts.is_empty() => BackendCommandInfo {
            executable: parts[0].clone(),
            argument_count: parts.len().saturating_sub(1),
        },
        _ => BackendCommandInfo {
            executable: "<invalid-command>".to_string(),
            argument_count: 0,
        },
    }
}

fn sanitize_backend_url(raw: &str) -> String {
    let Ok(mut url) = url::Url::parse(raw) else {
        return "<invalid-url>".to_string();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}
```

Change `BackendInfo.command` to `Option<BackendCommandInfo>`, `env` and `headers` to sorted vectors, and sanitize HTTP/A2A URLs in `backend_to_info` before returning.

- [ ] **Step 6: Implement secret-safe CLI rendering**

In `run_get_command`, render command metadata and presence-only key names:

```rust
if let Some(command) = &info.command {
    println!(
        "Command:     {} ({} argument(s) redacted)",
        command.executable, command.argument_count
    );
}
if !info.env.is_empty() {
    println!("Environment:");
    for key in &info.env { println!("  {key}=<set>"); }
}
if !info.headers.is_empty() {
    println!("Headers:");
    for key in &info.headers { println!("  {key}=<set>"); }
}
```

- [ ] **Step 7: Run targeted tests and static caller review**

Run the four commands from Step 4 plus:

```bash
rg -n "\.command\.as_deref|BackendInfo|\.env" src/commands src/gateway/ui tests
cargo test --all-features gateway::ui::backend_ops::tests -- --nocapture
```

Expected: all targeted tests pass; every compile-time caller is updated.

- [ ] **Step 8: Commit the DTO/CLI/status slice**

```bash
git add src/gateway/ui/backend_ops.rs src/commands/add_remove.rs src/backend/tests.rs tests/cli_secret_redaction.rs
git diff --cached --check
git commit -m "fix: redact backend diagnostics"
```

### Task 2: Metadata-only HTTP transport diagnostics

**Files:**
- Modify: `src/transport/http/mod.rs`
- Modify: `src/transport/http/tests.rs`

**Interfaces:**
- Produces: `sanitize_url_for_diagnostics(raw: &str) -> String`.
- Produces: `safe_request_error(context: &str, error: &reqwest::Error) -> Error`.
- Produces: `safe_http_status_error(status: StatusCode, body: &str) -> Error`.
- Consumes: existing session-expiry retry logic, tracing subscriber, and HTTP test server helpers.

- [ ] **Step 1: Add an in-memory tracing writer for tests**

In `src/transport/http/tests.rs`, implement a cloneable `MakeWriter` backed by `Arc<std::sync::Mutex<Vec<u8>>>` and a helper that runs a future under a DEBUG-level `tracing_subscriber::fmt()` subscriber, returning captured UTF-8 text.

- [ ] **Step 2: Add failing session/header/body/URL sentinel tests**

Add focused tests that:

1. Seed a raw session sentinel and call `build_mcp_headers(HeaderMode::Request { method: "ping" }, None)` under captured tracing.
2. Serve an SSE endpoint containing a query sentinel and call `establish_sse_connection` under captured tracing.
3. Return HTTP 400 with a credential-header sentinel and body sentinel, invoke `request`, and capture both tracing and `Error::to_string()`.
4. Use a configured base URL whose userinfo/query/fragment contain a URL sentinel and verify every diagnostic representation omits it.

Each test asserts useful fields such as `session_present`, `header_count`, and `HTTP 400` remain.

- [ ] **Step 3: Run the captured-log tests and verify RED**

Run:

```bash
cargo test --all-features http_diagnostics_ -- --nocapture
```

Expected: tests fail because current logs/errors contain the synthetic sentinels.

- [ ] **Step 4: Implement URL and reqwest error sanitizers**

Add helpers that strip URL userinfo/query/fragment and reduce reqwest failures to fixed categories:

```rust
fn safe_request_error(context: &str, error: &reqwest::Error) -> Error {
    let category = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_redirect() {
        "redirect rejected"
    } else {
        "request failed"
    };
    Error::Transport(format!("{context}: {category}"))
}
```

Use the URL sanitizer at every `url =` tracing field in the HTTP transport. Replace raw session fields with `session_present = true`, endpoint fields with `endpoint_received = true`, and raw header lists with `status` plus `header_count`.

- [ ] **Step 5: Preserve session-expiry classification without body exposure**

Read the non-success body only for classification. Return `Error::Transport(format!("HTTP {status}: session expired"))` when it contains `-32015` or case-insensitive `session not found`, otherwise return `Error::Transport(format!("HTTP {status}"))`. Update classifier tests to use only these safe shapes.

- [ ] **Step 6: Run targeted HTTP tests and leak lint**

Run:

```bash
cargo test --all-features http_diagnostics_ -- --nocapture
cargo test --all-features session_expired -- --nocapture
cargo test --all-features transport::http::tests -- --nocapture
python3 scripts/dev/test_cwe532_leak_lint.py
```

Expected: sentinel tests, retry tests, the complete HTTP unit module, and leak lint pass.

- [ ] **Step 7: Commit the HTTP diagnostic slice**

```bash
git add src/transport/http/mod.rs src/transport/http/tests.rs
git diff --cached --check
git commit -m "fix: redact HTTP transport diagnostics"
```

### Task 3: Exact and immutable npm MCP runtime bundle

**Files:**
- Create: `recovery/npm-runtime/package.json`
- Create: `recovery/npm-runtime/package-lock.json`
- Create: `recovery/npm-runtime/pins.json`
- Create: `recovery/npm-runtime/lib/runtime.mjs`
- Create: `recovery/npm-runtime/verify-runtime.mjs`
- Create: `recovery/npm-runtime/bootstrap-runtime.mjs`
- Create: `recovery/npm-runtime/smoke-runtime.mjs`
- Create: `recovery/npm-runtime/render-config.mjs`
- Create: `recovery/npm-runtime/test/runtime.test.mjs`
- Modify: `.gitignore`

**Interfaces:**
- Produces: canonical content digest, direct-pin and full-lock verification, safe atomic-publish plan, two-install evidence, npm audit JSON, stdio MCP smoke result, and reviewed digest-root YAML.
- Consumes: `/opt/homebrew/bin/node`, `/opt/homebrew/bin/npm`, exact package metadata, explicitly supplied absolute evidence root, and safe filesystem roots.

- [ ] **Step 1: Write Node tests before runtime tooling**

Use `node:test` and temporary directories to assert:

- version ranges are rejected;
- a direct SRI/version/bin mismatch is rejected;
- a symlink escaping the staged root is rejected;
- canonical tree hashing ignores timestamps but changes on bytes, mode, path, or symlink target;
- publishing refuses an existing digest path, seals every object against ordinary writes, and atomically creates a no-clobber digest alias to a same-filesystem verified object;
- publication reverifies alias identity, symlink containment, sealed modes, and content digest through the alias, rejecting both same-target alias replacement and a concurrent write through a descriptor opened before sealing;
- rendering rejects relative Node/install paths and emits only literal digest-root commands;
- a failed verification leaves its staging/evidence paths present.

Run `node --test recovery/npm-runtime/test/runtime.test.mjs`; expect failure because `lib/runtime.mjs` does not exist.

- [ ] **Step 2: Add exact manifest and direct pins**

Create a private `package.json` with exact dependency strings `3.2.4`, `2026.7.4`, `2026.7.10`, and `0.8.206`. Add `pins.json` with the four direct SRI/bin/entrypoint records and exact Node/npm path/version/SHA-256 records from the approved design.

- [ ] **Step 3: Implement minimal reusable verifier primitives**

In `lib/runtime.mjs`, implement exact-version checks, SHA-256 file verification, lockfile-v3 traversal requiring integrity for resolved registry packages, safe realpath containment, canonical directory hashing, exclusive directory creation, write-bit sealing plus atomic exclusive digest-alias publication and post-publication re-verification for a pre-positioned same-filesystem object, and digest-root command rendering. Document that mode sealing cannot defend against hostile same-owner processes that restore modes or retain writable descriptors. Do not implement recursive cleanup.

- [ ] **Step 4: Run Node unit tests and verify GREEN**

Run:

```bash
/opt/homebrew/bin/node --test recovery/npm-runtime/test/runtime.test.mjs
```

Expected: all runtime unit tests pass.

- [ ] **Step 5: Generate the full lock with an isolated cache**

Create the exact new evidence/cache path below (the command must fail rather than reuse it), then run from `recovery/npm-runtime`:

```bash
mkdir -p /Users/mikko/github/.worktrees/mcp-gateway-recovery-upstream/target/npm-runtime-evidence
mkdir /Users/mikko/github/.worktrees/mcp-gateway-recovery-upstream/target/npm-runtime-evidence/lock-20260721
/opt/homebrew/bin/npm install --package-lock-only --ignore-scripts --no-audit --no-fund --cache /Users/mikko/github/.worktrees/mcp-gateway-recovery-upstream/target/npm-runtime-evidence/lock-20260721
```

The cache path is a newly created evidence path, never the shared npm cache. Inspect the diff and ensure root dependency values remain exact.

- [ ] **Step 6: Implement verifier, bootstrap, smoke, and renderer CLIs**

`verify-runtime.mjs` verifies toolchain hashes (including the full npm module tree), manifest/lock/pins, installed package metadata, bin targets, symlink containment, and canonical digest. `bootstrap-runtime.mjs` exclusively creates two install roots and two empty cache/home/temp/config roots, invokes npm through pinned Node with no inherited credentials or npm configuration, verifies both trees, requires equal digests, runs npm audit without fixing, runs bounded smoke, and preserves all evidence on failure or success. `smoke-runtime.mjs` speaks newline-delimited JSON-RPC initialize/initialized/tools-list to all four child processes and validates Morph's platform ripgrep. `render-config.mjs` accepts only a verified evidence root and emits the four approved absolute command-only overrides under the internally derived digest directory below `/Users/mikko/.local/libexec/mcp-gateway/npm-runtime`.

- [ ] **Step 7: Run two-install determinism and stdio smoke**

Run bootstrap with a new absolute evidence root under `/Users/mikko/github/.worktrees/mcp-gateway-recovery-upstream/target/npm-runtime-evidence/`; bootstrap must create it exclusively and fail rather than reuse it. Every retry uses a fresh attempt suffix and retains earlier failed evidence. Expected evidence includes distinct cache/install paths, identical canonical tree digests, exact toolchain hashes, four successful initialize/tools-list transcripts without secret values, and an npm audit report plus exit status.

- [ ] **Step 8: Verify the reviewed config snippet**

Pass the successful evidence root—not a caller-supplied digest—to `render-config.mjs` and write the snippet into that same evidence root. The renderer must replay verification and derive the digest internally. Verify all command strings begin with `/opt/homebrew/bin/node`, reference the literal immutable digest root, contain no `npx`, preserve only filesystem roots `/Users/mikko/github` and `/Users/mikko/Documents`, and emit no environment/header/enabled/description fields that could overwrite private configuration state.

- [ ] **Step 9: Commit manifests and tooling only**

Ensure `git status --short` contains no `node_modules`, cache, evidence, audit output, or generated snippet. Then:

```bash
git add .gitignore recovery/npm-runtime
git diff --cached --check
git commit -m "build: pin npm backend runtime"
```

### Task 4: Full recovery verification and handoff

**Files:**
- Review all files changed since `b434d796`.

**Interfaces:**
- Consumes: all three implementation commits and retained staging evidence.
- Produces: exact commit hashes, runtime digest, artifact hashes, audit summary, config-snippet path, and explicit remaining credential/runtime failures.

- [ ] **Step 1: Run complete Rust gates**

```bash
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-features --quiet
cargo build --release --locked --bin mcp-gateway
```

- [ ] **Step 2: Run complete security/runtime gates**

```bash
python3 scripts/dev/test_cwe532_leak_lint.py
/opt/homebrew/bin/node --test recovery/npm-runtime/test/runtime.test.mjs
/opt/homebrew/bin/node recovery/npm-runtime/verify-runtime.mjs --evidence /Users/mikko/github/.worktrees/mcp-gateway-recovery-upstream/target/npm-runtime-evidence/final-20260721
```

Re-read retained bootstrap, smoke, and npm-audit evidence; do not expose secret values.

- [ ] **Step 3: Review scope and repository state**

```bash
git diff --check b434d796..HEAD
git diff --stat b434d796..HEAD
git status --short
rg -n "SENTINEL_|session_id\s*=\s*%|Headers: \{:?\}|HTTP \{status\}: \{body\}" src tests
```

Expected: clean worktree; no production sentinel or known raw-log pattern; only expected files changed. Record that GitNexus analysis could not run because the repo has no index and index/cache creation was prohibited.

- [ ] **Step 4: Report without live deployment**

Report each commit hash, test counts and exit status, release binary SHA-256, Node/npm hashes, canonical runtime digest, separate staging/cache paths, npm audit counts, four smoke results, reviewed snippet path/content summary, and remaining credential failures such as Parallel Search HTTP 401. Explicitly state that no live/private/shared-cache/PID/port mutation occurred.
