# Stdio Direct-Route Initialize Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an MCP client initialize a direct `/mcp/{backend}` route backed by an already-initialized stdio process without sending a second backend handshake, while retaining the backend's exact negotiated initialize result and configured startup timeout.

**Architecture:** `StdioTransport` remains the sole owner of its subprocess protocol session. It records the successful backend initialize result during its internal startup handshake, replays that result under a fresh transport request id for later client-side `initialize` calls, and consumes later `notifications/initialized` notifications because the subprocess already received that notification during startup. `Backend::start` enters through the same single-flight shared-slot path as route traffic, so a background warm-start and a cold direct request wait for one slow subprocess instead of racing two launches. Other methods, transports, gateway meta behavior, request-id restoration, and backend pool isolation stay unchanged.

**Tech Stack:** Rust 2024, Tokio, Axum router tests, deterministic local shell MCP fixtures.

## Global Constraints

- Start from exact reviewed commit `f67bf7a7253d4221bdb2c700631553ad1b700047` in an isolated worktree.
- Do not access or change live gateway processes, private configuration, protected ports, Spark, packages, or real model/network services.
- Use only deterministic fake MCP subprocesses in tests.
- Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --locked --quiet` before the final commit.

---

### Task 1: Reproduce direct-route duplicate initialization

**Files:**
- Modify: `src/gateway/router/tests.rs`

**Interfaces:**
- Consumes: `create_router`, `Backend`, `TransportConfig::Stdio`, and the existing direct `/mcp/{name}` route.
- Produces: A deterministic regression test proving one backend handshake serves a cold direct-route client through initialize, initialized notification, and tools/list.

- [x] **Step 1: Write the failing route test**

Create a temporary executable MCP fixture that delays its first initialize response, returns a distinctive initialize result, rejects a second backend initialize with JSON-RPC `-32600`, records received methods, and returns one fake tool from `tools/list`. Drive the route with:

```rust
initialize("direct-client-init")
notifications_initialized()
tools_list("direct-client-tools")
```

Assert the client receives the distinctive cached initialize result and its own request ids, `tools/list` succeeds within the backend's configured timeout, and the fixture observes exactly:

```text
initialize
notifications/initialized
tools/list
```

- [x] **Step 2: Run the new test and verify RED**

Run:

```bash
cargo test --locked gateway::router::tests::backend_handler_reuses_slow_stdio_handshake_for_direct_client -- --exact --nocapture
```

Expected: FAIL because the fixture receives a second `initialize` and returns `-32600 initialize called more than once`.

### Task 2: Cache and replay the stdio handshake

**Files:**
- Modify: `src/transport/stdio.rs`
- Test: `src/gateway/router/tests.rs`

**Interfaces:**
- Consumes: `StdioTransport::initialize`, `StdioTransport::negotiate_and_retry`, and `Transport::{request,notify}`.
- Produces: An in-memory `RwLock<Option<Value>>` snapshot of the successful backend initialize result, replayed only after transport initialization.

- [x] **Step 1: Record successful handshake results**

Add `initialize_result: RwLock<Option<Value>>` to `StdioTransport`, initialize it empty in `new`, and store a clone of the successful `result` before `finish_initialization()` on both normal and negotiated-success paths.

- [x] **Step 2: Replay duplicate client protocol plumbing locally**

At the beginning of `Transport::request`, allocate a fresh internal id and, when `method == "initialize"`, `connected == true`, and the cached result exists, return:

```rust
JsonRpcResponse::success(id, cached_result)
```

without writing to subprocess stdin. At the beginning of `Transport::notify`, return `Ok(())` for `notifications/initialized` only when the transport is already connected; the startup notification still goes to the subprocess because `connected` remains false until `finish_initialization` completes.

- [x] **Step 3: Run the focused test and verify GREEN**

Run the exact Task 1 command. Expected: PASS, with one initialize and one initialized notification observed by the fake backend.

### Task 3: Single-flight slow warm-start and direct-route readiness

**Files:**
- Modify: `src/backend/lifecycle.rs`
- Modify: `src/gateway/router/tests.rs`

**Interfaces:**
- Consumes: `Backend::{start,ensure_entry_started}`, the shared pool slot's `start_lock`, and the direct `/mcp/{name}` route.
- Produces: One shared startup operation when background warm-start overlaps a direct request.

- [x] **Step 1: Write the failing concurrent-start test**

Create a fake slow stdio backend that atomically acquires a temporary singleton directory and exits if a second process is launched. Start `Backend::start()` in a task, wait until its initialize delay begins, then issue a direct-route initialize request. Capture the response, await the warm-start, stop the fake backend, and only then assert that the route succeeded inside the configured timeout and the fixture observed one process launch.

- [x] **Step 2: Run the test and verify RED**

```bash
cargo test --locked gateway::router::tests::backend_handler_waits_for_inflight_slow_stdio_warm_start -- --exact --nocapture
```

Expected: FAIL because `Backend::start` bypasses the shared slot's `start_lock`, a second fake process is launched, and the route gets a transport failure.

- [x] **Step 3: Route explicit starts through the single-flight lifecycle**

Change `Backend::start` to call:

```rust
self.ensure_entry_started(&PoolKey::Shared).await?;
```

This reuses an already-connected shared transport and makes warm-start wait/notify behavior identical to request-triggered startup.

- [x] **Step 4: Run both route tests and verify GREEN**

```bash
cargo test --locked gateway::router::tests::backend_handler_reuses_slow_stdio_handshake_for_direct_client -- --exact
cargo test --locked gateway::router::tests::backend_handler_waits_for_inflight_slow_stdio_warm_start -- --exact
```

### Task 4: Verify scope and repository gates

**Files:**
- Verify: `src/transport/stdio.rs`
- Verify: `src/backend/lifecycle.rs`
- Verify: `src/gateway/router/tests.rs`
- Verify: `docs/superpowers/plans/2026-07-21-stdio-direct-initialize-compat.md`

**Interfaces:**
- Consumes: GitNexus change detection and repository quality commands.
- Produces: A clean, reviewable commit with exact hash and tree id.

- [x] **Step 1: Run focused and transport tests**

```bash
cargo test --locked gateway::router::tests::backend_handler_reuses_slow_stdio_handshake_for_direct_client -- --exact
cargo test --locked gateway::router::tests::backend_handler_waits_for_inflight_slow_stdio_warm_start -- --exact
cargo test --locked transport::stdio::tests --lib
```

- [x] **Step 2: Run all quality gates**

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --quiet
```

Execution note: formatting, production-library clippy, and the full test suite
pass. With the installed Rust 1.97.1 toolchain, all-target clippy reaches four
pre-existing `clippy::manual_assert_eq` findings in
`src/validator/rules_schema.rs`; that file is byte-identical to the reviewed
base and is intentionally outside this recovery fix. Re-running the complete
all-target gate while allowing only that already-present lint succeeds with no
other warnings.

- [x] **Step 3: Check graph and diff scope**

```bash
gitnexus detect-changes -r mcp-gateway --scope all
git diff --check
git status --short
```

Expected: only the stdio compatibility implementation, deterministic route test, and this plan are candidates for staging; generated index drift is excluded.

- [ ] **Step 4: Commit exact candidate**

```bash
git add src/transport/stdio.rs src/backend/lifecycle.rs src/gateway/router/tests.rs docs/superpowers/plans/2026-07-21-stdio-direct-initialize-compat.md
git commit -m "fix: bridge direct stdio initialization"
git rev-parse HEAD HEAD^{tree}
```
